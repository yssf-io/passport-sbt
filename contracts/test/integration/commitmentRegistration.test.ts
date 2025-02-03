import { expect } from "chai";
import { deploySystemFixtures } from "../utils/deployment";
import { DeployedActors } from "../utils/types";
import { ethers } from "hardhat";
import { CIRCUIT_CONSTANTS } from "../utils/constants";
import { RegisterVerifierId, DscVerifierId } from "../../../common/src/constants/constants";
import { ATTESTATION_ID } from "../utils/constants";
import { generateRegisterProof, generateDscProof } from "../utils/generateProof";
import { generateRandomFieldElement } from "../utils/utils";
import { TransactionReceipt, ZeroAddress } from "ethers";
import serialized_dsc_tree from '../../../common/pubkeys/serialized_dsc_tree.json';
import { LeanIMT } from "@openpassport/zk-kit-lean-imt";
import {poseidon2} from "poseidon-lite";

describe("Commitment Registration Tests", function () {
    this.timeout(0);

    let deployedActors: DeployedActors;
    let snapshotId: string;
    let baseDscProof: any;
    let baseRegisterProof: any;
    let dscProof: any;
    let registerProof: any;
    let registerSecret: any;

    before(async () => {
        deployedActors = await deploySystemFixtures();
        registerSecret = generateRandomFieldElement();
        baseDscProof = await generateDscProof(
            deployedActors.mockPassport.dsc,
        );
        baseRegisterProof = await generateRegisterProof(
            registerSecret,
            deployedActors.mockPassport
        );
        snapshotId = await ethers.provider.send("evm_snapshot", []);
    });

    beforeEach(async () => {
        dscProof = structuredClone(baseDscProof);
        registerProof = structuredClone(baseRegisterProof);
    });

    afterEach(async () => {
        await ethers.provider.send("evm_revert", [snapshotId]);
        snapshotId = await ethers.provider.send("evm_snapshot", []);
    });

    describe("Register Commitment", () => {

        describe("Initialization", () => {
            it("should have consistent addresses between registry and hub", async () => {
                const {hub, registry} = deployedActors;
                
                expect(await registry.hub()).to.equal(hub.target);
                expect(await hub.registry()).to.equal(registry.target);
            });
        });

        describe("Register DSC Pubkey", async () => {

            it("Should register DSC key commitment successfully", async () => {
                const {hub, registry} = deployedActors;

                const previousRoot = await registry.getDscKeyCommitmentMerkleRoot();
                const previousSize = await registry.getDscKeyCommitmentTreeSize();
                const tx = await hub.registerDscKeyCommitment(
                    DscVerifierId.dsc_rsa_sha256_65537_4096,
                    dscProof
                );

                const hashFunction = (a: bigint, b: bigint) => poseidon2([a, b]);
                const imt = new LeanIMT<bigint>(hashFunction);
                await imt.insert(BigInt(dscProof.pubSignals[CIRCUIT_CONSTANTS.DSC_TREE_LEAF_INDEX]));

                const receipt = await tx.wait() as TransactionReceipt;
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
                expect(currentRoot).to.be.equal(imt.root);
                expect(await registry.getDscKeyCommitmentTreeSize()).to.equal(previousSize + 1n);
                expect(await registry.getDscKeyCommitmentIndex(dscProof.pubSignals[CIRCUIT_CONSTANTS.DSC_TREE_LEAF_INDEX])).to.equal(index);
                expect(await registry.isRegisteredDscKeyCommitment(dscProof.pubSignals[CIRCUIT_CONSTANTS.DSC_TREE_LEAF_INDEX])).to.equal(true);
            });

            it("Should fail when called by proxy address", async () => {
                const {hubImpl} = deployedActors;
                await expect(
                    hubImpl.registerDscKeyCommitment(
                        DscVerifierId.dsc_rsa_sha256_65537_4096,
                        dscProof
                    )
                ).to.be.revertedWithCustomError(hubImpl, "UUPSUnauthorizedCallContext");
            });

            it("Should fail when the verifier is not set", async () => {
                const {hub} = deployedActors;
                await expect(
                    hub.registerDscKeyCommitment(
                        DscVerifierId.dsc_rsa_sha1_65537_4096,
                        dscProof
                    )
                ).to.be.revertedWithCustomError(hub, "NO_VERIFIER_SET");
            });

            it("Should fail when the csca root is invalid", async() => {
                const {hub} = deployedActors;
                dscProof.pubSignals[CIRCUIT_CONSTANTS.DSC_CSCA_ROOT_INDEX] = generateRandomFieldElement();
                await expect(
                    hub.registerDscKeyCommitment(
                        DscVerifierId.dsc_rsa_sha256_65537_4096,
                        dscProof
                    )
                ).to.be.revertedWithCustomError(hub, "INVALID_CSCA_ROOT");
            });

            it("Should fail when the proof is invalid", async () => {
                const {hub} = deployedActors;
                dscProof.a[0] = generateRandomFieldElement();
                await expect(
                    hub.registerDscKeyCommitment(
                        DscVerifierId.dsc_rsa_sha256_65537_4096,
                        dscProof
                    )
                ).to.be.revertedWithCustomError(hub, "INVALID_DSC_PROOF");
            });

            it("Should fail when registerDscKeyCommitment is called directly on implementation", async () => {
                const {registryImpl} = deployedActors;
                await expect(
                    registryImpl.registerDscKeyCommitment(
                        generateRandomFieldElement()
                    )
                ).to.be.revertedWithCustomError(registryImpl, "UUPSUnauthorizedCallContext");
            });

            it("Should fail when the registerDscKeyCommitment is called by non-hub address", async () => {
                const {registry,vcAndDisclose,register,dsc, owner} = deployedActors;
                const IdentityVerificationHubImplFactory = await ethers.getContractFactory("IdentityVerificationHubImplV1", owner);
                const hubImpl2 = await IdentityVerificationHubImplFactory.deploy();
                await hubImpl2.waitForDeployment();

                const initializeData = hubImpl2.interface.encodeFunctionData("initialize", [
                    registry.target,
                    vcAndDisclose.target,
                    [RegisterVerifierId.register_sha256_sha256_sha256_rsa_65537_4096],
                    [register.target],
                    [DscVerifierId.dsc_rsa_sha256_65537_4096],
                    [dsc.target]
                ]);
                const hubFactory = await ethers.getContractFactory("IdentityVerificationHub", owner);
                const hub2Proxy = await hubFactory.deploy(hubImpl2.target, initializeData);
                await hub2Proxy.waitForDeployment();

                const hub2 = await ethers.getContractAt("IdentityVerificationHubImplV1", hub2Proxy.target);

                await expect(
                    hub2.registerDscKeyCommitment(
                        DscVerifierId.dsc_rsa_sha256_65537_4096,
                        dscProof
                    )
                ).to.be.revertedWithCustomError(registry, "ONLY_HUB_CAN_ACCESS");
            });

            it("should fail registerDscKeyCommitment when hub address is not set", async () => {
                const {hub, registry} = deployedActors;

                await registry.updateHub(ZeroAddress);
                await expect(
                    hub.registerDscKeyCommitment(
                        DscVerifierId.dsc_rsa_sha256_65537_4096,
                        dscProof
                    )
                ).to.be.revertedWithCustomError(registry, "HUB_NOT_SET");
            });

            it("should fail when the dsc key commitment is already registered", async () => {
                const {hub, registry} = deployedActors;
                await hub.registerDscKeyCommitment(
                    DscVerifierId.dsc_rsa_sha256_65537_4096,
                    dscProof
                );
                await expect(
                    hub.registerDscKeyCommitment(
                        DscVerifierId.dsc_rsa_sha256_65537_4096,
                        dscProof
                    )
                ).to.be.revertedWithCustomError(registry, "REGISTERED_COMMITMENT");
            });

            it("should fail when getDscKeyCommitmentMerkleRoot is called by non-proxy", async () => {
                const {registryImpl} = deployedActors;
                await expect(
                    registryImpl.getDscKeyCommitmentMerkleRoot()
                ).to.be.revertedWithCustomError(registryImpl, "UUPSUnauthorizedCallContext");
            });

            it("should fail when checkDscKeyCommitmentMerkleRoot is called by non-proxy", async () => {
                const {registryImpl} = deployedActors;
                const root = generateRandomFieldElement();
                await expect(
                    registryImpl.checkDscKeyCommitmentMerkleRoot(root)
                ).to.be.revertedWithCustomError(registryImpl, "UUPSUnauthorizedCallContext");
            });

            it("should fail when getDscKeyCommitmentTreeSize is called by non-proxy", async () => {
                const {registryImpl} = deployedActors;
                await expect(
                    registryImpl.getDscKeyCommitmentTreeSize()
                ).to.be.revertedWithCustomError(registryImpl, "UUPSUnauthorizedCallContext");
            });

            it("should fail when getDscKeyCommitmentIndex is called by non-proxy", async () => {
                const {registryImpl} = deployedActors;
                const commitment =generateRandomFieldElement();
                await expect(
                    registryImpl.getDscKeyCommitmentIndex(commitment)
                ).to.be.revertedWithCustomError(registryImpl, "UUPSUnauthorizedCallContext");
            });

            it("should fail when registerDscKeyCommitment is called by non-proxy address", async () => {
                const { hubImpl } = deployedActors;
                await expect(
                    hubImpl.registerDscKeyCommitment(
                        DscVerifierId.dsc_rsa_sha256_65537_4096,
                        dscProof
                    )
                ).to.be.revertedWithCustomError(hubImpl, "UUPSUnauthorizedCallContext");
            });

        });

        describe("Register Passport Commitment", () => {
            before(async () => {
                const {registry} = deployedActors;
                const dscKeys = JSON.parse(serialized_dsc_tree);
                for (let i = 0; i < dscKeys[0].length; i++) {
                    await registry.devAddDscKeyCommitment(BigInt(dscKeys[0][i]));
                }
                snapshotId = await ethers.provider.send("evm_snapshot", []);
            });

            afterEach(async () => {
                await ethers.provider.send("evm_revert", [snapshotId]);
                snapshotId = await ethers.provider.send("evm_snapshot", []);
            });

            it("should register passport commitment successfully", async () => {
                const {hub, registry, mockPassport} = deployedActors;
    
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
                const nullifier = await registry.nullifiers(
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
                expect(nullifier).to.equal(true);
            });

            it("should fail when verifier is not set", async () => {
                const {hub} = deployedActors;
    
                registerProof.a[0] = generateRandomFieldElement();
    
                await expect(
                    hub.registerPassportCommitment(
                        RegisterVerifierId.register_sha1_sha1_sha1_rsa_65537_2048,
                        registerProof
                    )
                ).to.be.revertedWithCustomError(hub, "NO_VERIFIER_SET");
            });

            it("should fail when commitment root is invalid", async () => {
                const {hub} = deployedActors;

                const invalidCommitmentRoot = generateRandomFieldElement();

                registerProof.pubSignals[CIRCUIT_CONSTANTS.REGISTER_MERKLE_ROOT_INDEX] = invalidCommitmentRoot;
                await expect(
                    hub.registerPassportCommitment(
                        RegisterVerifierId.register_sha256_sha256_sha256_rsa_65537_4096,
                        registerProof
                    )
                ).to.be.revertedWithCustomError(hub, "INVALID_COMMITMENT_ROOT");
            });

            it("should fail when register proof verification fails", async () => {
                const {hub} = deployedActors;
    
                registerProof.a[0] = generateRandomFieldElement();
    
                await expect(
                    hub.registerPassportCommitment(
                        RegisterVerifierId.register_sha256_sha256_sha256_rsa_65537_4096,
                        registerProof
                    )
                ).to.be.revertedWithCustomError(hub, "INVALID_REGISTER_PROOF");
            });

            it("should fail when nullifier is already used", async () => {
                const {hub, registry, mockPassport} = deployedActors;
    
                const registerProof = await generateRegisterProof(
                    registerSecret,
                    mockPassport
                );
    
                await hub.registerPassportCommitment(
                    RegisterVerifierId.register_sha256_sha256_sha256_rsa_65537_4096,
                    registerProof
                );
                
                await expect(
                    hub.registerPassportCommitment(
                        RegisterVerifierId.register_sha256_sha256_sha256_rsa_65537_4096,
                        registerProof
                    )
                ).to.be.revertedWithCustomError(registry, "REGISTERED_COMMITMENT");
            });

            it("should fail when registerPassportCommitment is called by non-proxy address", async () => {
                const {hubImpl} = deployedActors;
                await expect(
                    hubImpl.registerPassportCommitment(
                        RegisterVerifierId.register_sha256_sha256_sha256_rsa_65537_4096,
                        registerProof
                    )
                ).to.be.revertedWithCustomError(hubImpl, "UUPSUnauthorizedCallContext");
            });

            it("should fail when registerCommitment is called by non-hub address", async () => {
                const {registry, vcAndDisclose, register, dsc, owner} = deployedActors;
                const IdentityVerificationHubImplFactory = await ethers.getContractFactory("IdentityVerificationHubImplV1", owner);
                const hubImpl2 = await IdentityVerificationHubImplFactory.deploy();
                await hubImpl2.waitForDeployment();

                const initializeData = hubImpl2.interface.encodeFunctionData("initialize", [
                    registry.target,
                    vcAndDisclose.target,
                    [RegisterVerifierId.register_sha256_sha256_sha256_rsa_65537_4096],
                    [register.target],
                    [DscVerifierId.dsc_rsa_sha256_65537_4096],
                    [dsc.target]
                ]);
                const hubFactory = await ethers.getContractFactory("IdentityVerificationHub", owner);
                const hub2Proxy = await hubFactory.deploy(hubImpl2.target, initializeData);
                await hub2Proxy.waitForDeployment();

                const hub2 = await ethers.getContractAt("IdentityVerificationHubImplV1", hub2Proxy.target);

                await expect(
                    hub2.registerPassportCommitment(
                        RegisterVerifierId.register_sha256_sha256_sha256_rsa_65537_4096,
                        registerProof
                    )
                ).to.be.revertedWithCustomError(registry, "ONLY_HUB_CAN_ACCESS");
            });

            it("should fail registerCommitment when hub address is not set", async () => {
                const {hub, registry} = deployedActors;

                await registry.updateHub(ZeroAddress);
                await expect(
                    hub.registerPassportCommitment(
                        RegisterVerifierId.register_sha256_sha256_sha256_rsa_65537_4096,
                        registerProof
                    )
                ).to.be.revertedWithCustomError(registry, "HUB_NOT_SET");
            });

            it("should fail when registerCommitment is called by non-proxy address", async() => {
                const {registryImpl} = deployedActors;

                const nullifier = generateRandomFieldElement();
                const commitment = generateRandomFieldElement();

                await expect(
                    registryImpl.registerCommitment(
                        ATTESTATION_ID.E_PASSPORT,
                        nullifier,
                        commitment
                    )
                ).to.be.revertedWithCustomError(registryImpl, "UUPSUnauthorizedCallContext");
            });

        });

    });
});