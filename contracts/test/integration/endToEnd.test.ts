import { expect } from "chai";
import { deploySystemFixtures } from "../utils/deployment";
import { DeployedActors } from "../utils/types";
import { ethers } from "hardhat";
import { CIRCUIT_CONSTANTS } from "../utils/constants";
import { RegisterVerifierId, DscVerifierId } from "../../../common/src/constants/constants";
import { ATTESTATION_ID } from "../utils/constants";
import { generateRegisterProof, generateDscProof, generateVcAndDiscloseProof } from "../utils/generateProof";
import { generateRandomFieldElement } from "../utils/utils";
import { TransactionReceipt, ZeroAddress } from "ethers";
import serialized_dsc_tree from '../../../common/pubkeys/serialized_dsc_tree.json';
import { LeanIMT } from "@openpassport/zk-kit-lean-imt";
import {poseidon2} from "poseidon-lite";
import { castFromScope } from "../../../common/src/utils/circuits/uuid";
import BalanceTree from "../utils/example/balance-tree";
import { formatCountriesList, reverseBytes } from "../../../common/src/utils/circuits/formatInputs";
import { Formatter } from "../utils/formatter";

describe("End to End Tests", function () {
    this.timeout(0);

    let deployedActors: DeployedActors;
    let snapshotId: string;

    before(async () => {
        deployedActors = await deploySystemFixtures();
        snapshotId = await ethers.provider.send("evm_snapshot", []);
    });

    afterEach(async () => {
        await ethers.provider.send("evm_revert", [snapshotId]);
        snapshotId = await ethers.provider.send("evm_snapshot", []);
    });

    it("register dsc key commitment, register identity commitment, verify commitment and disclose attrs and claim airdrop", async () => {
        const { hub, registry, mockPassport, owner, user1 } = deployedActors;

        // register dsc key
        // To increase test performance, we will just set one dsc key with groth16 proof
        // Other commitments are registered by dev function
        const dscKeys = JSON.parse(serialized_dsc_tree);
        let registerDscTx;
        const dscProof = await generateDscProof(
            mockPassport.dsc,
        );
        const registerSecret = generateRandomFieldElement();
        for (let i = 0; i < dscKeys[0].length; i++) {
            if (BigInt(dscKeys[0][i]) == dscProof.pubSignals[CIRCUIT_CONSTANTS.DSC_TREE_LEAF_INDEX]) {
                const previousRoot = await registry.getDscKeyCommitmentMerkleRoot();                
                const previousSize = await registry.getDscKeyCommitmentTreeSize();
                registerDscTx = await hub.registerDscKeyCommitment(
                    DscVerifierId.dsc_rsa_sha256_65537_4096,
                    dscProof
                );
                const receipt = await registerDscTx.wait() as TransactionReceipt;
                const event = receipt?.logs.find(
                    log => log.topics[0] === registry.interface.getEvent("DscKeyCommitmentRegistered").topicHash
                );
                const eventArgs = event ? registry.interface.decodeEventLog(
                    "DscKeyCommitmentRegistered",
                    event.data,
                    event.topics
                ) : null;

                const blockTimestamp = (await ethers.provider.getBlock(receipt.blockNumber))!.timestamp;
                const currentRoot = await registry.getDscKeyCommitmentMerkleRoot();
                const index = await registry.getDscKeyCommitmentIndex(dscProof.pubSignals[CIRCUIT_CONSTANTS.DSC_TREE_LEAF_INDEX]);

                expect(eventArgs?.commitment).to.equal(dscProof.pubSignals[CIRCUIT_CONSTANTS.DSC_TREE_LEAF_INDEX]);
                expect(eventArgs?.timestamp).to.equal(blockTimestamp);
                expect(eventArgs?.imtRoot).to.equal(currentRoot);
                expect(eventArgs?.imtIndex).to.equal(index);

                // Check state
                expect(currentRoot).to.not.equal(previousRoot);
                expect(await registry.getDscKeyCommitmentTreeSize()).to.equal(previousSize + 1n);
                expect(await registry.getDscKeyCommitmentIndex(dscProof.pubSignals[CIRCUIT_CONSTANTS.DSC_TREE_LEAF_INDEX])).to.equal(index);
                expect(await registry.isRegisteredDscKeyCommitment(dscProof.pubSignals[CIRCUIT_CONSTANTS.DSC_TREE_LEAF_INDEX])).to.equal(true);
            } else {
                await registry.devAddDscKeyCommitment(BigInt(dscKeys[0][i]));
            }
        };

        // register identity commitment
        const registerProof = await generateRegisterProof(
            registerSecret,
            mockPassport
        );

        const previousRoot = await registry.getIdentityCommitmentMerkleRoot();

        const hashFunction = (a: bigint, b: bigint) => poseidon2([a, b]);
        const imt = new LeanIMT<bigint>(hashFunction);
        await imt.insert(BigInt(registerProof.pubSignals[CIRCUIT_CONSTANTS.REGISTER_COMMITMENT_INDEX]));

        const tx = await hub.registerPassportCommitment(
            RegisterVerifierId.register_sha256_sha256_sha256_rsa_65537_4096,
            registerProof
        );
        const receipt = await tx.wait() as TransactionReceipt;
        const blockTimestamp = (await ethers.provider.getBlock(receipt.blockNumber))!.timestamp;

        const currentRoot = await registry.getIdentityCommitmentMerkleRoot();
        const size = await registry.getIdentityCommitmentMerkleTreeSize();
        const rootTimestamp = await registry.rootTimestamps(currentRoot);
        const index = await registry.getIdentityCommitmentIndex(registerProof.pubSignals[CIRCUIT_CONSTANTS.REGISTER_COMMITMENT_INDEX]);
        const identityNullifier = await registry.nullifiers(
            ATTESTATION_ID.E_PASSPORT,
            registerProof.pubSignals[CIRCUIT_CONSTANTS.REGISTER_NULLIFIER_INDEX]
        );

        const event = receipt?.logs.find(
            log => log.topics[0] === registry.interface.getEvent("CommitmentRegistered").topicHash
        );
        const eventArgs = event ? registry.interface.decodeEventLog(
            "CommitmentRegistered",
            event.data,
            event.topics
        ) : null;

        expect(eventArgs?.attestationId).to.equal(ATTESTATION_ID.E_PASSPORT);
        expect(eventArgs?.nullifier).to.equal(registerProof.pubSignals[CIRCUIT_CONSTANTS.REGISTER_NULLIFIER_INDEX]);
        expect(eventArgs?.commitment).to.equal(registerProof.pubSignals[CIRCUIT_CONSTANTS.REGISTER_COMMITMENT_INDEX]);
        expect(eventArgs?.timestamp).to.equal(blockTimestamp);
        expect(eventArgs?.imtRoot).to.equal(currentRoot);
        expect(eventArgs?.imtIndex).to.equal(0);

        expect(currentRoot).to.not.equal(previousRoot);
        expect(currentRoot).to.be.equal(imt.root);
        expect(size).to.equal(1);
        expect(rootTimestamp).to.equal(blockTimestamp);
        expect(index).to.equal(0);
        expect(identityNullifier).to.equal(true);

        const forbiddenCountriesList = ['AAA', 'ABC', 'CBA'];
        const countriesListPacked = reverseBytes(Formatter.bytesToHexString(new Uint8Array(formatCountriesList(forbiddenCountriesList))));

        const vcAndDiscloseProof = await generateVcAndDiscloseProof(
            registerSecret,
            BigInt(ATTESTATION_ID.E_PASSPORT).toString(),
            mockPassport,
            "test-scope",
            new Array(88).fill("1"),
            "1",
            imt,
            "20",
            undefined,
            undefined,
            forbiddenCountriesList,
            (await user1.getAddress()).slice(2)
        );

        const vcAndDiscloseHubProof = {
            olderThanEnabled: true,
            olderThan: "20",
            forbiddenCountriesEnabled: true,
            forbiddenCountriesListPacked: countriesListPacked,
            ofacEnabled: true,
            vcAndDiscloseProof: vcAndDiscloseProof
        }

        const result = await hub.verifyVcAndDisclose(vcAndDiscloseHubProof);

        expect(result.identityCommitmentRoot).to.equal(vcAndDiscloseProof.pubSignals[CIRCUIT_CONSTANTS.VC_AND_DISCLOSE_MERKLE_ROOT_INDEX]);
        expect(result.revealedDataPacked).to.have.lengthOf(3);
        expect(result.nullifier).to.equal(vcAndDiscloseProof.pubSignals[CIRCUIT_CONSTANTS.VC_AND_DISCLOSE_NULLIFIER_INDEX]);
        expect(result.attestationId).to.equal(vcAndDiscloseProof.pubSignals[CIRCUIT_CONSTANTS.VC_AND_DISCLOSE_ATTESTATION_ID_INDEX]);
        expect(result.userIdentifier).to.equal(vcAndDiscloseProof.pubSignals[CIRCUIT_CONSTANTS.VC_AND_DISCLOSE_USER_IDENTIFIER_INDEX]);
        expect(result.scope).to.equal(vcAndDiscloseProof.pubSignals[CIRCUIT_CONSTANTS.VC_AND_DISCLOSE_SCOPE_INDEX]);
        expect(result.forbiddenCountriesListPacked).to.equal(BigInt(countriesListPacked));

        const tokenFactory = await ethers.getContractFactory("AirdropToken");
        const token = await tokenFactory.connect(owner).deploy();
        await token.waitForDeployment();

        const airdropFactory = await ethers.getContractFactory("Airdrop");
        const airdrop = await airdropFactory.connect(owner).deploy(
            hub.target,
            registry.target,
            castFromScope("test-scope"),
            ATTESTATION_ID.E_PASSPORT,
            token.target,
            rootTimestamp,
            true,
            20,
            true,
            countriesListPacked,
            true,
        );
        await airdrop.waitForDeployment();

        await token.connect(owner).mint(airdrop.target, BigInt(1000000000000000000));

        await airdrop.connect(owner).openRegistration();
        await airdrop.connect(user1).registerAddress(vcAndDiscloseProof);
        await airdrop.connect(owner).closeRegistration();

        const tree = new BalanceTree([
            { account: await user1.getAddress(), amount: BigInt(1000000000000000000) }
        ]);
        const merkleRoot = tree.getHexRoot();
        await airdrop.connect(owner).setMerkleRoot(merkleRoot);
        await airdrop.connect(owner).openClaim();
        const merkleProof = tree.getProof(0, await user1.getAddress(), BigInt(1000000000000000000));
        const claimTx = await airdrop.connect(user1).claim(
            0, 
            BigInt(1000000000000000000), 
            merkleProof
        );
        const claimReceipt = await claimTx.wait() as TransactionReceipt;

        const claimEvent = claimReceipt?.logs.find(
            log => log.topics[0] === airdrop.interface.getEvent("Claimed").topicHash
        );
        const claimEventArgs = claimEvent ? airdrop.interface.decodeEventLog(
            "Claimed",
            claimEvent.data,
            claimEvent.topics
        ) : null;

        expect(claimEventArgs?.index).to.equal(0);
        expect(claimEventArgs?.amount).to.equal(BigInt(1000000000000000000));
        expect(claimEventArgs?.account).to.equal(await user1.getAddress());

        const balance = await token.balanceOf(await user1.getAddress());
        expect(balance).to.equal(BigInt(1000000000000000000));

        const isClaimed = await airdrop.claimed(await user1.getAddress());
        expect(isClaimed).to.be.true;

        const readableData = await hub.getReadableRevealedData(
            [
                result.revealedDataPacked[0],
                result.revealedDataPacked[1],
                result.revealedDataPacked[2]
            ],
            ['0', '1', '2', '3', '4', '5', '6', '7', '8']
        );

        expect(readableData[0]).to.equal('FRA');
        expect(readableData[1]).to.deep.equal([ 'ALPHONSE HUGHUES ALBERT', 'DUPONT' ]);
        expect(readableData[2]).to.equal('15AA81234');
        expect(readableData[3]).to.equal('FRA');
        expect(readableData[4]).to.equal('31-01-94');
        expect(readableData[5]).to.equal('M');
        expect(readableData[6]).to.equal('31-10-40');
        expect(readableData[7]).to.equal(20n);
        expect(readableData[8]).to.equal(1n);
    });
});