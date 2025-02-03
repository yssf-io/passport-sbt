import { expect } from "chai";
import { deploySystemFixtures } from "../utils/deployment";
import { DeployedActors } from "../utils/types";
import { ethers } from "hardhat";
import { CIRCUIT_CONSTANTS } from "../utils/constants";
import { ATTESTATION_ID } from "../utils/constants";
import {generateVcAndDiscloseProof } from "../utils/generateProof";
import { LeanIMT } from "@openpassport/zk-kit-lean-imt";
import { poseidon2 } from "poseidon-lite";
import { generateCommitment } from "../../../common/src/utils/passports/passport";
import { generateRandomFieldElement } from "../utils/utils";
import BalanceTree from "../utils/example/balance-tree";
import { castFromScope } from "../../../common/src/utils/circuits/uuid";
import { formatCountriesList, reverseBytes } from '../../../common/src/utils/circuits/formatInputs';
import { Formatter } from "../utils/formatter";

describe("Airdrop", () => {
    let deployedActors: DeployedActors;
    let snapshotId: string;
    let airdrop: any;
    let token: any;
    let baseVcAndDiscloseProof: any;
    let vcAndDiscloseProof: any;
    let registerSecret: any;
    let imt: any;
    let commitment: any;
    let nullifier: any;
    let forbiddenCountriesList: any;
    let countriesListPacked: any;

    before(async () => {
        deployedActors = await deploySystemFixtures();

        registerSecret = generateRandomFieldElement();
        nullifier = generateRandomFieldElement();
        commitment = generateCommitment(registerSecret, ATTESTATION_ID.E_PASSPORT, deployedActors.mockPassport);

        forbiddenCountriesList = ['AAA', 'ABC', 'CBA'];
        
        const hashFunction = (a: bigint, b: bigint) => poseidon2([a, b]);
        imt = new LeanIMT<bigint>(hashFunction);
        await imt.insert(BigInt(commitment));

        baseVcAndDiscloseProof = await generateVcAndDiscloseProof(
            registerSecret,
            BigInt(ATTESTATION_ID.E_PASSPORT).toString(),
            deployedActors.mockPassport,
            "test-airdrop",
            new Array(88).fill("1"),
            "1",
            imt,
            "20",
            undefined,
            undefined,
            forbiddenCountriesList,
            (await deployedActors.user1.getAddress()).slice(2)
        );


        const tokenFactory = await ethers.getContractFactory("AirdropToken");
        token = await tokenFactory.connect(deployedActors.owner).deploy();
        await token.waitForDeployment();

        await deployedActors.registry.connect(deployedActors.owner).devAddIdentityCommitment(
            ATTESTATION_ID.E_PASSPORT,
            nullifier,
            commitment
        );

        const root = await deployedActors.registry.getIdentityCommitmentMerkleRoot();
        const timestamp = await deployedActors.registry.rootTimestamps(root);
        countriesListPacked = reverseBytes(Formatter.bytesToHexString(new Uint8Array(formatCountriesList(forbiddenCountriesList))));

        const airdropFactory = await ethers.getContractFactory("Airdrop");
        airdrop = await airdropFactory.connect(deployedActors.owner).deploy(
            deployedActors.hub.target,
            deployedActors.registry.target,
            castFromScope("test-airdrop"),
            ATTESTATION_ID.E_PASSPORT,
            token.target,
            timestamp,
            true,
            20,
            true,
            countriesListPacked,
            true,
        );
        await airdrop.waitForDeployment();
        
        const mintAmount = ethers.parseEther("424242424242");
        await token.mint(airdrop.target, mintAmount);

        snapshotId = await ethers.provider.send("evm_snapshot", []);
    });

    beforeEach(async () => {
        vcAndDiscloseProof = structuredClone(baseVcAndDiscloseProof);
    });

    afterEach(async () => {
        await ethers.provider.send("evm_revert", [snapshotId]);
        snapshotId = await ethers.provider.send("evm_snapshot", []);
    });

    it("should able to open registration by owner", async () => {
        const { owner } = deployedActors;
        const tx = await airdrop.connect(owner).openRegistration();
        const receipt = await tx.wait();
        const event = receipt?.logs.find(
            (log: any) => log.topics[0] === airdrop.interface.getEvent("RegistrationOpen").topicHash
        );
        expect(event).to.not.be.null;
        expect(await airdrop.isRegistrationOpen()).to.be.true;
    });

    it("should not able to open registration by non-owner", async () => {
        const { user1 } = deployedActors;
        await expect(airdrop.connect(user1).openRegistration())
            .to.be.revertedWithCustomError(airdrop, "OwnableUnauthorizedAccount")
            .withArgs(await user1.getAddress());
    });

    it("should able to close registration by owner", async () => {
        const { owner} = deployedActors;
        await airdrop.connect(owner).openRegistration();
        const tx = await airdrop.connect(owner).closeRegistration();
        const receipt = await tx.wait();
        const event = receipt?.logs.find(
            (log: any) => log.topics[0] === airdrop.interface.getEvent("RegistrationClose").topicHash
        );
        expect(event).to.not.be.null;
        expect(await airdrop.isRegistrationOpen()).to.be.false;
    });

    it("should not able to close registration by non-owner", async () => {
        const { user1 } = deployedActors;
        await expect(airdrop.connect(user1).closeRegistration())
            .to.be.revertedWithCustomError(airdrop, "OwnableUnauthorizedAccount")
            .withArgs(await user1.getAddress());
    });

    it("should able to open claim by owner", async () => {
        const { owner} = deployedActors;
        const tx = await airdrop.connect(owner).openClaim();
        const receipt = await tx.wait();

        const event = receipt?.logs.find(
            (log: any) => log.topics[0] === airdrop.interface.getEvent("ClaimOpen").topicHash
        );
        expect(event).to.not.be.null;
        expect(await airdrop.isClaimOpen()).to.be.true;
    });

    it("should not able to open claim by non-owner", async () => {
        const { user1 } = deployedActors;
        await expect(airdrop.connect(user1).openClaim())
            .to.be.revertedWithCustomError(airdrop, "OwnableUnauthorizedAccount")
            .withArgs(await user1.getAddress());
    });

    it("should able to close claim by owner", async () => {
        const { owner } = deployedActors;
        await airdrop.connect(owner).openClaim();
        const tx = await airdrop.connect(owner).closeClaim();
        const receipt = await tx.wait();
        const event = receipt?.logs.find(
            (log: any) => log.topics[0] === airdrop.interface.getEvent("ClaimClose").topicHash
        );
        expect(event).to.not.be.null;
        expect(await airdrop.isClaimOpen()).to.be.false;
    });

    it("should not able to close claim by owner", async () => {
        const { owner, user1 } = deployedActors;
        await airdrop.connect(owner).openClaim();
        await expect(
            airdrop.connect(user1).closeClaim()
        ).to.be.revertedWithCustomError(airdrop, "OwnableUnauthorizedAccount");
    });

    it("should able to set merkle root by owner", async () => {
        const { owner } = deployedActors;
        const merkleRoot = generateRandomFieldElement();
        await airdrop.connect(owner).setMerkleRoot(merkleRoot);
        expect(await airdrop.merkleRoot()).to.be.equal(merkleRoot);
    });

    it("should not able to set merkle root by non-owner", async () => {
        const { user1 } = deployedActors;
        const merkleRoot = generateRandomFieldElement();
        await expect(airdrop.connect(user1).setMerkleRoot(merkleRoot))
            .to.be.revertedWithCustomError(airdrop, "OwnableUnauthorizedAccount")
            .withArgs(await user1.getAddress());
    });

    it("should able to register address by user", async () => {
        const { owner, user1 } = deployedActors;

        await airdrop.connect(owner).openRegistration();
        const tx = await airdrop.connect(user1).registerAddress(vcAndDiscloseProof);
        const receipt = await tx.wait();
        
        const event = receipt?.logs.find(
            (log: any) => log.topics[0] === airdrop.interface.getEvent("UserIdentifierRegistered").topicHash
        );
        const eventArgs = event ? airdrop.interface.decodeEventLog(
            "UserIdentifierRegistered",
            event.data,
            event.topics
        ) : null;

        expect(eventArgs?.registeredUserIdentifier).to.be.equal(await user1.getAddress());

        const appNullifier = vcAndDiscloseProof.pubSignals[CIRCUIT_CONSTANTS.VC_AND_DISCLOSE_NULLIFIER_INDEX];
        expect(eventArgs?.nullifier).to.be.equal(appNullifier);

        const nullifierToId = await airdrop.getNullifier(appNullifier);
        expect(nullifierToId).to.be.equal(await user1.getAddress());

        const isRegistered = await airdrop.isRegistered(await user1.getAddress());
        expect(isRegistered).to.be.equal(true);
        const isRegisteredFalse = await airdrop.isRegistered(await owner.getAddress());
    });

    it("should not able to register address by user if registration is closed", async () => {
        const { owner, user1 } = deployedActors;

        await airdrop.connect(owner).closeRegistration();
        await expect(airdrop.connect(user1).registerAddress(vcAndDiscloseProof))
            .to.be.revertedWithCustomError(airdrop, "RegistrationNotOpen");
    });

    it("should not able to register address by user if scope is invalid", async () => {
        const { owner, user1 } = deployedActors;

        vcAndDiscloseProof = await generateVcAndDiscloseProof(
            registerSecret,
            BigInt(ATTESTATION_ID.E_PASSPORT).toString(),
            deployedActors.mockPassport,
            "test-airdrop-invalid",
            new Array(88).fill("1"),
            "1",
            imt,
            "20",
        );

        await airdrop.connect(owner).openRegistration();
        await expect(airdrop.connect(user1).registerAddress(vcAndDiscloseProof))
            .to.be.revertedWithCustomError(airdrop, "InvalidScope");
    });

    it("should not able to register address by user if nullifier is already registered", async () => {
        const { owner, user1 } = deployedActors;

        await airdrop.connect(owner).openRegistration();
        await airdrop.connect(user1).registerAddress(vcAndDiscloseProof);
        await expect(airdrop.connect(user1).registerAddress(vcAndDiscloseProof))
            .to.be.revertedWithCustomError(airdrop, "RegisteredNullifier");
    });

    it("should not able to register address by user if attestation id is invalid", async () => {
        const { registry, owner, user1 } = deployedActors;

        const invalidCommitment = generateCommitment(registerSecret, ATTESTATION_ID.INVALID_ATTESTATION_ID, deployedActors.mockPassport);
        
        await registry.connect(owner).devAddIdentityCommitment(
            ATTESTATION_ID.INVALID_ATTESTATION_ID,
            nullifier,
            invalidCommitment
        );

        const hashFunction = (a: bigint, b: bigint) => poseidon2([a, b]);
        const invalidImt = new LeanIMT<bigint>(hashFunction);
        await invalidImt.insert(BigInt(commitment));
        await invalidImt.insert(BigInt(invalidCommitment));

        vcAndDiscloseProof = await generateVcAndDiscloseProof(
            registerSecret,
            BigInt(ATTESTATION_ID.INVALID_ATTESTATION_ID).toString(),
            deployedActors.mockPassport,
            "test-airdrop",
            new Array(88).fill("1"),
            "1",
            invalidImt,
            "20",
        );

        await airdrop.connect(owner).openRegistration();
        await expect(airdrop.connect(user1).registerAddress(vcAndDiscloseProof))
            .to.be.revertedWithCustomError(airdrop, "InvalidAttestationId");
    });

    it("should not able to register address when rootTimestamp is different", async () => {
        const {registry, owner, user1, mockPassport} = deployedActors;

        const secondCommitment = generateCommitment(registerSecret, ATTESTATION_ID.INVALID_ATTESTATION_ID, mockPassport);
        await registry.devAddIdentityCommitment(
            ATTESTATION_ID.E_PASSPORT,
            nullifier,
            secondCommitment
        );

        const hashFunction = (a: bigint, b: bigint) => poseidon2([a, b]);
        const invalidImt = new LeanIMT<bigint>(hashFunction);
        await invalidImt.insert(BigInt(commitment));
        await invalidImt.insert(BigInt(secondCommitment));

        vcAndDiscloseProof = await generateVcAndDiscloseProof(
            registerSecret,
            BigInt(ATTESTATION_ID.E_PASSPORT).toString(),
            deployedActors.mockPassport,
            "test-airdrop",
            new Array(88).fill("1"),
            "1",
            invalidImt,
            "20",
            undefined,
            undefined,
            forbiddenCountriesList,
            (await deployedActors.user1.getAddress()).slice(2)
        );

        await airdrop.connect(owner).openRegistration();
        await expect(airdrop.connect(user1).registerAddress(vcAndDiscloseProof))
            .to.be.revertedWithCustomError(airdrop, "InvalidTimestamp");
    });

    it("should allow registration when targetRootTimestamp is 0", async () => {
        const { hub, registry, owner, user1 } = deployedActors;

        const airdropFactory = await ethers.getContractFactory("Airdrop");
        const newAirdrop = await airdropFactory.connect(owner).deploy(
            hub.target,
            registry.target,
            castFromScope("test-airdrop"),
            ATTESTATION_ID.E_PASSPORT,
            token.target,
            0,
            true,
            20,
            true,
            countriesListPacked,
            true,
        );
        console.log()
        await newAirdrop.waitForDeployment();

        await newAirdrop.connect(owner).openRegistration();
        await expect(newAirdrop.connect(user1).registerAddress(vcAndDiscloseProof))
            .to.not.be.reverted;
    });

    it("should revert with InvalidTimestamp when root timestamp does not match", async () => {
        const { hub, registry, owner, user1 } = deployedActors;
        
        const airdropFactory = await ethers.getContractFactory("Airdrop");
        const newAirdrop = await airdropFactory.connect(owner).deploy(
            hub.target,
            registry.target,
            castFromScope("test-airdrop"),
            ATTESTATION_ID.E_PASSPORT,
            token.target,
            123456789,
            true,
            20,
            true,
            countriesListPacked,
            true,
        );
        await newAirdrop.waitForDeployment();

        await newAirdrop.connect(owner).openRegistration();
        await expect(newAirdrop.connect(user1).registerAddress(vcAndDiscloseProof))
            .to.be.revertedWithCustomError(newAirdrop, "InvalidTimestamp");
    });

    it("should return correct scope", async () => {
        const scope = await airdrop.getScope();
        expect(scope).to.equal(castFromScope("test-airdrop"));
    });

    it("should return correct attestation id", async () => {
        const attestationId = await airdrop.getAttestationId();
        expect(attestationId).to.equal(ATTESTATION_ID.E_PASSPORT);
    });

    it("should return correct merkle root", async () => {
        const { owner } = deployedActors;
        const merkleRoot = generateRandomFieldElement();
        
        await airdrop.connect(owner).setMerkleRoot(merkleRoot);
        const storedRoot = await airdrop.merkleRoot();
        expect(storedRoot).to.equal(merkleRoot);
    });

    it("should return correct token address", async () => {
        const tokenAddress = await airdrop.token();
        expect(tokenAddress).to.equal(token.target);
    });

    it("should able to claim token by user", async () => {
        const { owner, user1 } = deployedActors;

        await airdrop.connect(owner).openRegistration();
        await airdrop.connect(user1).registerAddress(vcAndDiscloseProof);
        await airdrop.connect(owner).closeRegistration();

        const tree = new BalanceTree([{ account: await user1.getAddress(), amount: BigInt(1000000000000000000) }]);
        const root = tree.getHexRoot();

        await airdrop.connect(owner).setMerkleRoot(root);

        await airdrop.connect(owner).openClaim();
        const merkleProof = tree.getProof(0, await user1.getAddress(), BigInt(1000000000000000000));
        const tx = await airdrop.connect(user1).claim(0, BigInt(1000000000000000000), merkleProof);
        const receipt = await tx.wait();

        const event = receipt?.logs.find(
            (log: any) => log.topics[0] === airdrop.interface.getEvent("Claimed").topicHash
        );
        const eventArgs = event ? airdrop.interface.decodeEventLog(
            "Claimed",
            event.data,
            event.topics
        ) : null;

        expect(eventArgs?.index).to.equal(0);
        expect(eventArgs?.amount).to.equal(BigInt(1000000000000000000));
        expect(eventArgs?.account).to.equal(await user1.getAddress());

        const balance = await token.balanceOf(await user1.getAddress());
        expect(balance).to.equal(BigInt(1000000000000000000));

        const isClaimed = await airdrop.claimed(await user1.getAddress());
        expect(isClaimed).to.be.true;
    });

    it("should not able to claim token by user if registration is not closed", async () => {
        const { owner, user1 } = deployedActors;

        await airdrop.connect(owner).openRegistration();
        await airdrop.connect(user1).registerAddress(vcAndDiscloseProof);

        const tree = new BalanceTree([{ account: await user1.getAddress(), amount: BigInt(1000000000000000000) }]);
        const root = tree.getHexRoot();

        await airdrop.connect(owner).setMerkleRoot(root);

        await airdrop.connect(owner).openClaim();
        const merkleProof = tree.getProof(0, await user1.getAddress(), BigInt(1000000000000000000));
        await expect(airdrop.connect(user1).claim(0, BigInt(1000000000000000000), merkleProof))
            .to.be.revertedWithCustomError(airdrop, "RegistrationNotClosed");

        const isClaimed = await airdrop.claimed(await user1.getAddress());
        expect(isClaimed).to.be.false;
    });

    it("should not able to claim token by user if claim is not open", async () => {
        const { owner, user1 } = deployedActors;

        await airdrop.connect(owner).openRegistration();
        await airdrop.connect(user1).registerAddress(vcAndDiscloseProof);
        await airdrop.connect(owner).closeRegistration();

        const tree = new BalanceTree([{ account: await user1.getAddress(), amount: BigInt(1000000000000000000) }]);
        const root = tree.getHexRoot();

        await airdrop.connect(owner).setMerkleRoot(root);

        const merkleProof = tree.getProof(0, await user1.getAddress(), BigInt(1000000000000000000));
        await expect(airdrop.connect(user1).claim(0, BigInt(1000000000000000000), merkleProof))
            .to.be.revertedWithCustomError(airdrop, "ClaimNotOpen");

        const isClaimed = await airdrop.claimed(await user1.getAddress());
        expect(isClaimed).to.be.false;
    });

    it("should not able to claim token by user if user has already claimed", async () => {
        const { owner, user1 } = deployedActors;

        await airdrop.connect(owner).openRegistration();
        await airdrop.connect(user1).registerAddress(vcAndDiscloseProof);
        await airdrop.connect(owner).closeRegistration();
        const tree = new BalanceTree([{ account: await user1.getAddress(), amount: BigInt(1000000000000000000) }]);
        const root = tree.getHexRoot();

        await airdrop.connect(owner).setMerkleRoot(root);

        await airdrop.connect(owner).openClaim();
        const merkleProof = tree.getProof(0, await user1.getAddress(), BigInt(1000000000000000000));
        await airdrop.connect(user1).claim(0, BigInt(1000000000000000000), merkleProof);
        await expect(airdrop.connect(user1).claim(0, BigInt(1000000000000000000), merkleProof))
            .to.be.revertedWithCustomError(airdrop, "AlreadyClaimed");


        const balance = await token.balanceOf(await user1.getAddress());
        expect(balance).to.equal(BigInt(1000000000000000000));

        const isClaimed = await airdrop.claimed(await user1.getAddress());
        expect(isClaimed).to.be.true;
    });

    it("should not able to claim token by user if merkle proof is invalid", async () => {
        const { owner, user1 } = deployedActors;

        await airdrop.connect(owner).openRegistration();
        await airdrop.connect(user1).registerAddress(vcAndDiscloseProof);
        await airdrop.connect(owner).closeRegistration();
        const tree = new BalanceTree([{ account: await user1.getAddress(), amount: BigInt(1000000000000000000) }]);
        const root = tree.getHexRoot();

        await airdrop.connect(owner).setMerkleRoot(root);

        await airdrop.connect(owner).openClaim();
        const merkleProof = tree.getProof(0, await user1.getAddress(), BigInt(1000000000000000000));
        merkleProof[0] = generateRandomFieldElement().toString();
        await expect(airdrop.connect(user1).claim(0, BigInt(1000000000000000000), merkleProof))
            .to.be.revertedWithCustomError(airdrop, "InvalidProof");

        const isClaimed = await airdrop.claimed(await user1.getAddress());
        expect(isClaimed).to.be.false;
    });

    it("should not able to claim token by user if user is not registered", async () => {
        const { owner, user1, user2 } = deployedActors;

        await airdrop.connect(owner).openRegistration();
        await airdrop.connect(user1).registerAddress(vcAndDiscloseProof);
        await airdrop.connect(owner).closeRegistration();

        const tree = new BalanceTree([
            { account: await user1.getAddress(), amount: BigInt(1000000000000000000) },
            { account: await user2.getAddress(), amount: BigInt(1000000000000000000) }
        ]);
        const root = tree.getHexRoot();

        await airdrop.connect(owner).setMerkleRoot(root);
        await airdrop.connect(owner).openClaim();

        const merkleProof = tree.getProof(1, await user2.getAddress(), BigInt(1000000000000000000));
        await expect(airdrop.connect(user2).claim(1, BigInt(1000000000000000000), merkleProof))
            .to.be.revertedWithCustomError(airdrop, "NotRegistered")
            .withArgs(await user2.getAddress());

        const isClaimed = await airdrop.claimed(await user2.getAddress());
        expect(isClaimed).to.be.false;
    });

    it("should able to set verification config by owner", async () => {
        const { owner } = deployedActors;
        const newVerificationConfig = {
            olderThanEnabled: false,
            olderThan: 25,
            forbiddenCountriesEnabled: false,
            forbiddenCountriesListPacked: countriesListPacked,
            ofacEnabled: false
        };

        await airdrop.connect(owner).setVerificationConfig(newVerificationConfig);
        const storedConfig = await airdrop.getVerificationConfig();
        
        expect(storedConfig.olderThanEnabled).to.equal(newVerificationConfig.olderThanEnabled);
        expect(storedConfig.olderThan).to.equal(newVerificationConfig.olderThan);
        expect(storedConfig.forbiddenCountriesEnabled).to.equal(newVerificationConfig.forbiddenCountriesEnabled);
        expect(storedConfig.forbiddenCountriesListPacked).to.equal(newVerificationConfig.forbiddenCountriesListPacked);
        expect(storedConfig.ofacEnabled).to.equal(newVerificationConfig.ofacEnabled);
    });

    it("should not able to set verification config by non-owner", async () => {
        const { user1 } = deployedActors;
        const newVerificationConfig = {
            olderThanEnabled: false,
            olderThan: 25,
            forbiddenCountriesEnabled: false,
            forbiddenCountriesListPacked: countriesListPacked,
            ofacEnabled: false
        };

        await expect(airdrop.connect(user1).setVerificationConfig(newVerificationConfig))
            .to.be.revertedWithCustomError(airdrop, "OwnableUnauthorizedAccount")
            .withArgs(await user1.getAddress());
    });

    it("should return correct verification config", async () => {
        const config = await airdrop.getVerificationConfig();
        expect(config.olderThanEnabled).to.equal(true);
        expect(config.olderThan).to.equal(20);
        expect(config.forbiddenCountriesEnabled).to.equal(true);
        expect(config.forbiddenCountriesListPacked).to.equal(countriesListPacked);
        expect(config.ofacEnabled).to.equal(true);
    });

});
