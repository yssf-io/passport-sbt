import { expect } from "chai";
import { deploySystemFixtures } from "../utils/deployment";
import { DeployedActors } from "../utils/types";
import { ethers } from "hardhat";
import { ZeroAddress } from "ethers";
import { generateRandomFieldElement } from "../utils/utils";
import { LeanIMT } from "@openpassport/zk-kit-lean-imt";
import { poseidon2 } from "poseidon-lite";
describe("Unit Tests for IdentityRegistry", () => {
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

    describe("Initialization", () => {
        it("should initialize registry with correct hub address", async () => {
            const {registry, hub} = deployedActors;
            expect(await registry.hub()).to.equal(hub.target);
            
            const initializedFiler = registry.filters.RegistryInitialized;
            const events = await registry.queryFilter(initializedFiler);
            expect(events.length).to.equal(1);
            expect(events[0].args.hub).to.equal(ZeroAddress);
            const updatedFiler = registry.filters.HubUpdated;
            const updatedEvents = await registry.queryFilter(updatedFiler);
            expect(updatedEvents.length).to.equal(1);
            expect(updatedEvents[0].args.hub).to.equal(hub.target);
        });

        
        it("should not allow direct initialization of registry implementation", async () => {
            const {owner, hub} = deployedActors;
            
            const PoseidonT3Factory = await ethers.getContractFactory("PoseidonT3", owner);
            const poseidonT3 = await PoseidonT3Factory.deploy();
            await poseidonT3.waitForDeployment();

            const RegistryFactory = await ethers.getContractFactory(
                "IdentityRegistryImplV1", 
                {
                    libraries: {
                        PoseidonT3: poseidonT3.target
                    }
                },
                owner
            );
            const registryImpl = await RegistryFactory.deploy();

            await expect(
                registryImpl.initialize(hub.target)
            ).to.be.revertedWithCustomError(registryImpl, "InvalidInitialization");
        });

        it("should not allow initialization after initialized", async () => {
            const { registry, hub } = deployedActors;
            
            await expect(
                registry.initialize(hub.target)
            ).to.be.revertedWithCustomError(registry, "InvalidInitialization");
        });
    });

    describe("View functions", () => {
        it("should return hub address", async () => {
            const {hub, registry} = deployedActors;
            expect(await registry.hub()).to.equal(hub.target);
        });

        it("should fail if hub is called by non-proxy", async () => {
            const {registryImpl, user1} = deployedActors;
            await expect(registryImpl.connect(user1).hub()).to.be.revertedWithCustomError(registryImpl, "UUPSUnauthorizedCallContext");
        });

        it("should return nullifier state", async () => {
            const {registry} = deployedActors;
            const attestationId = generateRandomFieldElement();
            const nullifier = generateRandomFieldElement();
            await registry.devChangeNullifierState(attestationId, nullifier, true);
            const state = await registry.nullifiers(attestationId, nullifier);
            expect(state).to.equal(true);
        });

        it("should fail if nullifier is called by non-proxy", async () => {
            const {registryImpl, user1} = deployedActors;
            const attestationId = generateRandomFieldElement();
            const nullifier = generateRandomFieldElement();
            await expect(registryImpl.connect(user1).nullifiers(attestationId, nullifier)).to.be.revertedWithCustomError(registryImpl, "UUPSUnauthorizedCallContext");
        });

        it("should return dsc key commitment state", async () => {
            const {registry} = deployedActors;
            const dscCommitment = generateRandomFieldElement();
            const state = true;
            await registry.devChangeDscKeyCommitmentState(dscCommitment, state);
            const dscKeyCommitmentState = await registry.isRegisteredDscKeyCommitment(dscCommitment);
            expect(dscKeyCommitmentState).to.equal(state);
        });

        it("should fail if dsc key commitment state is called by non-proxy", async () => {
            const {registryImpl, user1} = deployedActors;
            const dscCommitment = generateRandomFieldElement();
            await expect(registryImpl.connect(user1).isRegisteredDscKeyCommitment(dscCommitment)).to.be.revertedWithCustomError(registryImpl, "UUPSUnauthorizedCallContext");
        });

        it("should return root timestamp", async () => {
            const {registry} = deployedActors;
            const commitment = generateRandomFieldElement();
            const timestamp = (await ethers.provider.getBlock("latest"))!.timestamp;
            const tx = await registry.devAddIdentityCommitment(commitment, timestamp, generateRandomFieldElement());
            const receipt = await tx.wait() as TransactionReceipt;
            const blockTimestamp = (await ethers.provider.getBlock(receipt.blockNumber))!.timestamp;
            const root = await registry.getIdentityCommitmentMerkleRoot();
            const rootTimestamp = await registry.rootTimestamps(root);
            expect(rootTimestamp).to.equal(blockTimestamp);
        });

        it("should fail if root timestamp is called by non-proxy", async () => {
            const {registryImpl, user1} = deployedActors;
            const root = generateRandomFieldElement();
            await expect(registryImpl.connect(user1).rootTimestamps(root)).to.be.revertedWithCustomError(registryImpl, "UUPSUnauthorizedCallContext");
        });

        it("should return true if checkIdentityCommitmentRoot is called with valid root", async () => {
            const {registry} = deployedActors;
            const commitment = generateRandomFieldElement();
            const timestamp = (await ethers.provider.getBlock("latest"))!.timestamp;
            await registry.devAddIdentityCommitment(commitment, timestamp, generateRandomFieldElement());
            const root = await registry.getIdentityCommitmentMerkleRoot();
            expect(await registry.checkIdentityCommitmentRoot(root)).to.equal(true);
        });

        it("should return false if checkIdentityCommitmentRoot is called with invalid root", async () => {
            const {registry} = deployedActors;
            const commitment = generateRandomFieldElement();
            const timestamp = (await ethers.provider.getBlock("latest"))!.timestamp;
            await registry.devAddIdentityCommitment(commitment, timestamp, generateRandomFieldElement());
            const root = generateRandomFieldElement();
            expect(await registry.checkIdentityCommitmentRoot(root)).to.equal(false);
        });

        it("should fail if checkIdentityCommitmentRoot is called by non-proxy", async () => {
            const {registryImpl, user1} = deployedActors;
            const root = generateRandomFieldElement();
            await expect(registryImpl.connect(user1).checkIdentityCommitmentRoot(root)).to.be.revertedWithCustomError(registryImpl, "UUPSUnauthorizedCallContext");
        });

        it("should return identity commitment merkle tree size", async () => {
            const {registry} = deployedActors;
            const attestationId = generateRandomFieldElement();
            const nullifier = generateRandomFieldElement();
            const commitment = generateRandomFieldElement();
            await registry.devAddIdentityCommitment(attestationId, nullifier, commitment);
            const size = await registry.getIdentityCommitmentMerkleTreeSize();
            expect(size).to.equal(1);
        });

        it("should fail if identity commitment merkle tree size is called by non-proxy", async () => {
            const {registryImpl, user1} = deployedActors;
            await expect(registryImpl.connect(user1).getIdentityCommitmentMerkleTreeSize()).to.be.revertedWithCustomError(registryImpl, "UUPSUnauthorizedCallContext");
        });

        it("should return identity commitment merkle root", async () => {
            const {registry} = deployedActors;
            const attestationId = generateRandomFieldElement();
            const nullifier = generateRandomFieldElement();
            const commitment = generateRandomFieldElement();
            await registry.devAddIdentityCommitment(attestationId, nullifier, commitment);
            const root = await registry.getIdentityCommitmentMerkleRoot();

            const hashFunction = (a: bigint, b: bigint) => poseidon2([a, b]);
            const imt = new LeanIMT<bigint>(hashFunction);
            imt.insert(BigInt(commitment));
            expect(imt.root).to.equal(root);
        });

        it("should fail if identity commitment merkle root is called by non-proxy", async () => {
            const {registryImpl, user1} = deployedActors;
            await expect(registryImpl.connect(user1).getIdentityCommitmentMerkleRoot()).to.be.revertedWithCustomError(registryImpl, "UUPSUnauthorizedCallContext");
        });

        it("should return identity commitment index", async () => {
            const {registry} = deployedActors;
            const attestationId = generateRandomFieldElement();
            const nullifier = generateRandomFieldElement();
            const commitment = generateRandomFieldElement();
            await registry.devAddIdentityCommitment(attestationId, nullifier, commitment);
            const index = await registry.getIdentityCommitmentIndex(commitment);
            expect(index).to.equal(0);
        });

        it("should fail if identity commitment index is called by non-proxy", async () => {
            const {registryImpl, user1} = deployedActors;
            const commitment = generateRandomFieldElement();
            await expect(registryImpl.connect(user1).getIdentityCommitmentIndex(commitment)).to.be.revertedWithCustomError(registryImpl, "UUPSUnauthorizedCallContext");
        });

        it("should return ofac root", async () => {
            const {registry, owner} = deployedActors;
            const root = generateRandomFieldElement();
            await registry.connect(owner).updateOfacRoot(root);
            const ofacRoot = await registry.getOfacRoot();
            expect(ofacRoot).to.equal(root);
        });

        it("should fail if ofac root is called by non-proxy", async () => {
            const {registryImpl, user1} = deployedActors;
            await expect(registryImpl.connect(user1).getOfacRoot()).to.be.revertedWithCustomError(registryImpl, "UUPSUnauthorizedCallContext");
        });

        it("should return true if checkOfacRoot is called with valid root", async () => {
            const {registry, owner} = deployedActors;
            const root = generateRandomFieldElement();
            await registry.connect(owner).updateOfacRoot(root);
            expect(await registry.checkOfacRoot(root)).to.equal(true);
        });

        it("should return false if checkOfacRoot is called with invalid root", async () => {
            const {registry} = deployedActors;
            const root = generateRandomFieldElement();
            expect(await registry.checkOfacRoot(root)).to.equal(false);
        });

        it("should fail if checkOfacRoot is called by non-proxy", async () => {
            const {registryImpl, user1} = deployedActors;
            const root = generateRandomFieldElement();
            await expect(registryImpl.connect(user1).checkOfacRoot(root)).to.be.revertedWithCustomError(registryImpl, "UUPSUnauthorizedCallContext");
        });

        it("should return csca root", async () => {
            const {registry, owner} = deployedActors;
            const root = generateRandomFieldElement();
            await registry.connect(owner).updateCscaRoot(root);
            const cscaRoot = await registry.getCscaRoot();
            expect(cscaRoot).to.equal(root);
        });

        it("should fail if csca root is called by non-proxy", async () => {
            const {registryImpl, user1} = deployedActors;
            await expect(registryImpl.connect(user1).getCscaRoot()).to.be.revertedWithCustomError(registryImpl, "UUPSUnauthorizedCallContext");
        });

        it("should return true if checkCscaRoot is called with valid root", async () => {
            const {registry, owner} = deployedActors;
            const root = generateRandomFieldElement();
            await registry.connect(owner).updateCscaRoot(root);
            expect(await registry.checkCscaRoot(root)).to.equal(true);
        });

        it("should return false if checkCscaRoot is called with invalid root", async () => {
            const {registry} = deployedActors;
            const root = generateRandomFieldElement();
            expect(await registry.checkCscaRoot(root)).to.equal(false);
        });

        it("should fail if checkCscaRoot is called by non-proxy", async () => {
            const {registryImpl, user1} = deployedActors;
            const root = generateRandomFieldElement();
            await expect(registryImpl.connect(user1).checkCscaRoot(root)).to.be.revertedWithCustomError(registryImpl, "UUPSUnauthorizedCallContext");
        });

        
    })

    describe("Update functions", () => {
        it("should update hub address", async () => {
            const { registry, user1 } = deployedActors;
            const newHubAddress = await user1.getAddress();

            await expect(registry.updateHub(newHubAddress))
                .to.emit(registry, "HubUpdated")
                .withArgs(newHubAddress);

            expect(await registry.hub()).to.equal(newHubAddress);
        });

        it("should not update hub address if caller is not owner", async () => {
            const { registry, user1 } = deployedActors;
            const newHubAddress = await user1.getAddress();

            await expect(registry.connect(user1).updateHub(newHubAddress)).to.be.revertedWithCustomError(registry, "OwnableUnauthorizedAccount");
        });

        it("should not update hub address if caller is not proxy", async () => {
            const { registryImpl, user1 } = deployedActors;
            const newHubAddress = await user1.getAddress();

            await expect(registryImpl.connect(user1).updateHub(newHubAddress)).to.be.revertedWithCustomError(registryImpl, "UUPSUnauthorizedCallContext");
        });

        it("should update OFAC root", async () => {
            const { registry } = deployedActors;
            const newOfacRoot = generateRandomFieldElement();

            await expect(registry.updateOfacRoot(newOfacRoot))
                .to.emit(registry, "OfacRootUpdated")
                .withArgs(newOfacRoot);

            expect(await registry.getOfacRoot()).to.equal(newOfacRoot);
        });

        it("should not update OFAC root if caller is not owner", async () => {
            const { registry, user1 } = deployedActors;
            const newOfacRoot = generateRandomFieldElement();

            await expect(registry.connect(user1).updateOfacRoot(newOfacRoot)).to.be.revertedWithCustomError(registry, "OwnableUnauthorizedAccount");
        });

        it("should not update OFAC root if caller is not proxy", async () => {
            const { registryImpl, user1 } = deployedActors;
            const newOfacRoot = generateRandomFieldElement();

            await expect(registryImpl.connect(user1).updateOfacRoot(newOfacRoot)).to.be.revertedWithCustomError(registryImpl, "UUPSUnauthorizedCallContext");
        });

        it("should update CSCA root", async () => {
            const { registry } = deployedActors;
            const newCscaRoot = generateRandomFieldElement();

            await expect(registry.updateCscaRoot(newCscaRoot))
                .to.emit(registry, "CscaRootUpdated")
                .withArgs(newCscaRoot);

            expect(await registry.getCscaRoot()).to.equal(newCscaRoot);
        });

        it("should not update CSCA root if caller is not owner", async () => {
            const { registry, user1 } = deployedActors;
            const newCscaRoot = generateRandomFieldElement();

            await expect(registry.connect(user1).updateCscaRoot(newCscaRoot)).to.be.revertedWithCustomError(registry, "OwnableUnauthorizedAccount");
        });

        it("should not update CSCA root if caller is not proxy", async () => {
            const { registryImpl, user1 } = deployedActors;
            const newCscaRoot = generateRandomFieldElement();

            await expect(registryImpl.connect(user1).updateCscaRoot(newCscaRoot)).to.be.revertedWithCustomError(registryImpl, "UUPSUnauthorizedCallContext");
        });

        it("should be able to add commitment by owner", async () => {
            const { registry } = deployedActors;
            const attestationId = generateRandomFieldElement();
            const nullifier = generateRandomFieldElement();
            const commitment = generateRandomFieldElement();

            const tx = await registry.devAddIdentityCommitment(attestationId, nullifier, commitment);
            const receipt = await tx.wait();
            const blockTimestamp = (await ethers.provider.getBlock("latest"))!.timestamp;
            
            const event = receipt?.logs.find(
                log => log.topics[0] === registry.interface.getEvent("DevCommitmentRegistered").topicHash
            );
            const eventArgs = event ? registry.interface.decodeEventLog(
                "DevCommitmentRegistered",
                event.data,
                event.topics
            ) : null;

            const currentRoot = await registry.getIdentityCommitmentMerkleRoot();
            const rootTimestamp = await registry.rootTimestamps(currentRoot);

            expect(eventArgs?.attestationId).to.equal(attestationId);
            expect(eventArgs?.nullifier).to.equal(nullifier);
            expect(eventArgs?.commitment).to.equal(commitment);
            expect(eventArgs?.timestamp).to.equal(blockTimestamp);
            expect(rootTimestamp).to.equal(blockTimestamp);
        });

        it("should not add commitment if caller is not owner", async () => {
            const { registry, user1 } = deployedActors;
            const attestationId = generateRandomFieldElement();
            const nullifier = generateRandomFieldElement();
            const commitment = generateRandomFieldElement();

            await expect(registry.connect(user1).devAddIdentityCommitment(attestationId, nullifier, commitment)).to.be.revertedWithCustomError(registry, "OwnableUnauthorizedAccount");
        });

        it("should not add commitment if caller is not proxy", async () => {
            const { registryImpl, user1 } = deployedActors;
            const attestationId = generateRandomFieldElement();
            const nullifier = generateRandomFieldElement();
            const commitment = generateRandomFieldElement();

            await expect(registryImpl.connect(user1).devAddIdentityCommitment(attestationId, nullifier, commitment)).to.be.revertedWithCustomError(registryImpl, "UUPSUnauthorizedCallContext");
        });

        it("should be able to update commitment by owner", async () => {
            const { registry } = deployedActors;
            const attestationId = generateRandomFieldElement();
            const nullifier = generateRandomFieldElement();
            const commitment = generateRandomFieldElement();
            await registry.devAddIdentityCommitment(attestationId, nullifier, commitment);
            const newCommitment = generateRandomFieldElement();
            const tx = await registry.devUpdateCommitment(commitment, newCommitment, []);
            const receipt = await tx.wait();
            const blockTimestamp = (await ethers.provider.getBlock("latest"))!.timestamp;
            const event = receipt?.logs.find(
                log => log.topics[0] === registry.interface.getEvent("DevCommitmentUpdated").topicHash
            );
            const eventArgs = event ? registry.interface.decodeEventLog(
                "DevCommitmentUpdated",
                event.data,
                event.topics
            ) : null;

            const currentRoot = await registry.getIdentityCommitmentMerkleRoot();

            expect(eventArgs?.oldLeaf).to.equal(commitment);
            expect(eventArgs?.newLeaf).to.equal(newCommitment);
            expect(eventArgs?.imtRoot).to.equal(currentRoot);
            expect(eventArgs?.timestamp).to.equal(blockTimestamp);
        });

        it("should not update commitment if caller is not owner", async () => {
            const { registry, user1 } = deployedActors;
            const attestationId = generateRandomFieldElement();
            const nullifier = generateRandomFieldElement();
            const commitment = generateRandomFieldElement();
            await registry.devAddIdentityCommitment(attestationId, nullifier, commitment);
            const newCommitment = generateRandomFieldElement();
            await expect(registry.connect(user1).devUpdateCommitment(commitment, newCommitment, [])).to.be.revertedWithCustomError(registry, "OwnableUnauthorizedAccount");
        });

        it("should not update commitment if caller is not proxy", async () => {
            const { registry, registryImpl, user1 } = deployedActors;
            const attestationId = generateRandomFieldElement();
            const nullifier = generateRandomFieldElement();
            const commitment = generateRandomFieldElement();
            await registry.devAddIdentityCommitment(attestationId, nullifier, commitment);
            const newCommitment = generateRandomFieldElement();
            await expect(registryImpl.connect(user1).devUpdateCommitment(commitment, newCommitment, [])).to.be.revertedWithCustomError(registryImpl, "UUPSUnauthorizedCallContext");
        });

        it("able to remove commitment by owner", async () => {
            const { registry, owner, user1 } = deployedActors;
            const attestationId = generateRandomFieldElement();
            const nullifier = generateRandomFieldElement();
            const commitment = generateRandomFieldElement();
            await registry.devAddIdentityCommitment(attestationId, nullifier, commitment);
            const tx = await registry.devRemoveCommitment(commitment, []);
            const receipt = await tx.wait();
            const blockTimestamp = (await ethers.provider.getBlock("latest"))!.timestamp;
            const event = receipt?.logs.find(
                log => log.topics[0] === registry.interface.getEvent("DevCommitmentRemoved").topicHash
            );
            const eventArgs = event ? registry.interface.decodeEventLog(
                "DevCommitmentRemoved",
                event.data,
                event.topics
            ) : null;

            const currentRoot = await registry.getIdentityCommitmentMerkleRoot();

            expect(eventArgs?.oldLeaf).to.equal(commitment);
            expect(eventArgs?.imtRoot).to.equal(currentRoot);
            expect(eventArgs?.timestamp).to.equal(blockTimestamp);
        });

        it("should not remove commitment if caller is not owner", async () => {
            const { registry, user1 } = deployedActors;
            const attestationId = generateRandomFieldElement();
            const nullifier = generateRandomFieldElement();
            const commitment = generateRandomFieldElement();
            await registry.devAddIdentityCommitment(attestationId, nullifier, commitment);
            await expect(registry.connect(user1).devRemoveCommitment(commitment, [])).to.be.revertedWithCustomError(registry, "OwnableUnauthorizedAccount");
        });

        it("should not remove commitment if caller is not proxy", async () => {
            const { registry, registryImpl, user1 } = deployedActors;
            const attestationId = generateRandomFieldElement();
            const nullifier = generateRandomFieldElement();
            const commitment = generateRandomFieldElement();
            await registry.devAddIdentityCommitment(attestationId, nullifier, commitment);
            await expect(registryImpl.connect(user1).devRemoveCommitment(commitment, [])).to.be.revertedWithCustomError(registryImpl, "UUPSUnauthorizedCallContext");
        });

        it("should able to add dsc key commitment by owner", async () => {
            const { registry } = deployedActors;
            const dscCommitment = generateRandomFieldElement();
            const tx = await registry.devAddDscKeyCommitment(dscCommitment);
            const receipt = await tx.wait();
            const event = receipt?.logs.find(
                log => log.topics[0] === registry.interface.getEvent("DevDscKeyCommitmentRegistered").topicHash
            );
            const eventArgs = event ? registry.interface.decodeEventLog(
                "DevDscKeyCommitmentRegistered",
                event.data,
                event.topics
            ) : null;

            const currentRoot = await registry.getDscKeyCommitmentMerkleRoot();
            const index = await registry.getDscKeyCommitmentIndex(dscCommitment);
            expect(eventArgs?.commitment).to.equal(dscCommitment);
            expect(eventArgs?.imtRoot).to.equal(currentRoot);
            expect(eventArgs?.imtIndex).to.equal(index);
        });

        it("should not add dsc key commitment if caller is not owner", async () => {
            const { registry, user1 } = deployedActors;
            const dscCommitment = generateRandomFieldElement();
            await expect(registry.connect(user1).devAddDscKeyCommitment(dscCommitment)).to.be.revertedWithCustomError(registry, "OwnableUnauthorizedAccount");
        });

        it("should not add dsc key commitment if caller is not proxy", async () => {
            const { registryImpl, user1 } = deployedActors;
            const dscCommitment = generateRandomFieldElement();
            await expect(registryImpl.connect(user1).devAddDscKeyCommitment(dscCommitment)).to.be.revertedWithCustomError(registryImpl, "UUPSUnauthorizedCallContext");
        });

        it("should able to update dsc key commitment by owner", async () => {
            const { registry } = deployedActors;
            const dscCommitment = generateRandomFieldElement();
            const newDscCommitment = generateRandomFieldElement();
            await registry.devAddDscKeyCommitment(dscCommitment);
            const tx = await registry.devUpdateDscKeyCommitment(dscCommitment, newDscCommitment, []);
            const receipt = await tx.wait();
            const event = receipt?.logs.find(
                log => log.topics[0] === registry.interface.getEvent("DevDscKeyCommitmentUpdated").topicHash
            );
            const eventArgs = event ? registry.interface.decodeEventLog(
                "DevDscKeyCommitmentUpdated",
                event.data,
                event.topics
            ) : null;

            const currentRoot = await registry.getDscKeyCommitmentMerkleRoot();

            expect(eventArgs?.oldLeaf).to.equal(dscCommitment);
            expect(eventArgs?.newLeaf).to.equal(newDscCommitment);
            expect(eventArgs?.imtRoot).to.equal(currentRoot);
        });

        it("should not update dsc key commitment if caller is not owner", async () => {
            const { registry, user1 } = deployedActors;
            const dscCommitment = generateRandomFieldElement();
            const newDscCommitment = generateRandomFieldElement();
            await registry.devAddDscKeyCommitment(dscCommitment);
            await expect(registry.connect(user1).devUpdateDscKeyCommitment(dscCommitment, newDscCommitment, [])).to.be.revertedWithCustomError(registry, "OwnableUnauthorizedAccount");
        });

        it("should not update dsc key commitment if caller is not proxy", async () => {
            const { registry, registryImpl, user1 } = deployedActors;
            const dscCommitment = generateRandomFieldElement();
            const newDscCommitment = generateRandomFieldElement();
            await registry.devAddDscKeyCommitment(dscCommitment);
            await expect(registryImpl.connect(user1).devUpdateDscKeyCommitment(dscCommitment, newDscCommitment, [])).to.be.revertedWithCustomError(registryImpl, "UUPSUnauthorizedCallContext");
        });

        it("should able to remove dsc key commitment by owner", async () => {
            const { registry } = deployedActors;
            const dscCommitment = generateRandomFieldElement();
            await registry.devAddDscKeyCommitment(dscCommitment);
            const tx = await registry.devRemoveDscKeyCommitment(dscCommitment, []);
            const receipt = await tx.wait();
            const event = receipt?.logs.find(
                log => log.topics[0] === registry.interface.getEvent("DevDscKeyCommitmentRemoved").topicHash
            );
            const eventArgs = event ? registry.interface.decodeEventLog(
                "DevDscKeyCommitmentRemoved",
                event.data,
                event.topics
            ) : null;

            const currentRoot = await registry.getDscKeyCommitmentMerkleRoot();

            expect(eventArgs?.oldLeaf).to.equal(dscCommitment);
            expect(eventArgs?.imtRoot).to.equal(currentRoot);
        });

        it("should not remove dsc key commitment if caller is not owner", async () => {
            const { registry, user1 } = deployedActors;
            const dscCommitment = generateRandomFieldElement();
            await registry.devAddDscKeyCommitment(dscCommitment);
            await expect(registry.connect(user1).devRemoveDscKeyCommitment(dscCommitment, [])).to.be.revertedWithCustomError(registry, "OwnableUnauthorizedAccount");
        });

        it("should not remove dsc key commitment if caller is not proxy", async () => {
            const { registry, registryImpl, user1 } = deployedActors;
            const dscCommitment = generateRandomFieldElement();
            await registry.devAddDscKeyCommitment(dscCommitment);
            await expect(registryImpl.connect(user1).devRemoveDscKeyCommitment(dscCommitment, [])).to.be.revertedWithCustomError(registryImpl, "UUPSUnauthorizedCallContext");
        });

        it("able to change nullifier state by owner", async () => {
            const { registry, owner, user1 } = deployedActors;
            const attestationId = generateRandomFieldElement();
            const nullifier = generateRandomFieldElement();

            const tx = await registry.devChangeNullifierState(attestationId, nullifier, false);
            const receipt = await tx.wait() as TransactionReceipt;
            const event = receipt?.logs.find(
                log => log.topics[0] === registry.interface.getEvent("DevNullifierStateChanged").topicHash
            );
            const eventArgs = event ? registry.interface.decodeEventLog(
                "DevNullifierStateChanged",
                event.data,
                event.topics
            ) : null;

            const nullifierCheck = await registry.nullifiers(attestationId, nullifier);
            expect(eventArgs?.attestationId).to.equal(attestationId);
            expect(eventArgs?.nullifier).to.equal(nullifier);
            expect(eventArgs?.state).to.equal(false);
            expect(nullifierCheck).to.equal(false);
        });

        it("should not change nullifier state if caller is not owner", async () => {
            const { registry, user1 } = deployedActors;
            const attestationId = generateRandomFieldElement();
            const nullifier = generateRandomFieldElement();
            await expect(registry.connect(user1).devChangeNullifierState(attestationId, nullifier, false)).to.be.revertedWithCustomError(registry, "OwnableUnauthorizedAccount");
        });

        it("should not change nullifier state if caller is not proxy", async () => {
            const { registryImpl, user1 } = deployedActors;
            const attestationId = generateRandomFieldElement();
            const nullifier = generateRandomFieldElement();
            await expect(registryImpl.connect(user1).devChangeNullifierState(attestationId, nullifier, false)).to.be.revertedWithCustomError(registryImpl, "UUPSUnauthorizedCallContext");
        });

        it("able to change dsc key commitment state by owner", async () => {
            const { registry } = deployedActors;
            const dscCommitment = generateRandomFieldElement();
            const state = true;
            const tx = await registry.devChangeDscKeyCommitmentState(dscCommitment, state);
            const receipt = await tx.wait() as TransactionReceipt;
            const event = receipt?.logs.find(
                log => log.topics[0] === registry.interface.getEvent("DevDscKeyCommitmentStateChanged").topicHash
            );
            const eventArgs = event ? registry.interface.decodeEventLog(
                "DevDscKeyCommitmentStateChanged",
                event.data,
                event.topics
            ) : null;

            expect(eventArgs?.commitment).to.equal(dscCommitment);
            expect(eventArgs?.state).to.equal(state);

            const dscKeyCommitmentState = await registry.isRegisteredDscKeyCommitment(dscCommitment);
            expect(dscKeyCommitmentState).to.equal(state);
        });

        it("should not change dsc key commitment state if caller is not owner", async () => {
            const { registry, user1 } = deployedActors;
            const dscCommitment = generateRandomFieldElement();
            const state = true;
            await expect(registry.connect(user1).devChangeDscKeyCommitmentState(dscCommitment, state)).to.be.revertedWithCustomError(registry, "OwnableUnauthorizedAccount");
        });

        it("should not change dsc key commitment state if caller is not proxy", async () => {
            const { registryImpl, user1 } = deployedActors;
            const dscCommitment = generateRandomFieldElement();
            const state = true;
            await expect(registryImpl.connect(user1).devChangeDscKeyCommitmentState(dscCommitment, state)).to.be.revertedWithCustomError(registryImpl, "UUPSUnauthorizedCallContext");
        });
    });

    describe("Upgradeability", () => {
        it("should preserve registry state after upgrade", async () => {
            const {registry, owner} = deployedActors;

            const initialHub = await registry.hub();
            const initialCscaRoot = await registry.getCscaRoot();
            const initialOfacRoot = await registry.getOfacRoot();

            const attestationId = generateRandomFieldElement();
            const nullifier = generateRandomFieldElement();
            const commitment = generateRandomFieldElement();
            const tx = await registry.devAddIdentityCommitment(attestationId, nullifier, commitment);
            const receipt = await tx.wait() as TransactionReceipt;
            const registeredTimestamp = (await ethers.provider.getBlock(receipt.blockNumber))!.timestamp;

            const initialCommitmentRoot = await registry.getIdentityCommitmentMerkleRoot();
            const initialTreeSize = await registry.getIdentityCommitmentMerkleTreeSize();

            const PoseidonT3Factory = await ethers.getContractFactory("PoseidonT3", owner);
            const poseidonT3 = await PoseidonT3Factory.deploy();
            await poseidonT3.waitForDeployment();

            const IdentityRegistryImplFactory = await ethers.getContractFactory(
                "IdentityRegistryImplV1", 
                {
                    libraries: {
                        PoseidonT3: poseidonT3.target
                    }
                },
                owner
            );

            const registryV2Implementation = await IdentityRegistryImplFactory.deploy();
            await registryV2Implementation.waitForDeployment();

            await registry.connect(owner).upgradeToAndCall(
                registryV2Implementation.target,
                "0x"
            );

            const registryV2 = await ethers.getContractAt("IdentityRegistryImplV1", registry.target);
            
            expect(await registryV2.hub()).to.equal(initialHub);
            expect(await registryV2.getCscaRoot()).to.equal(initialCscaRoot);
            expect(await registryV2.getOfacRoot()).to.equal(initialOfacRoot);
            expect(await registryV2.getIdentityCommitmentMerkleRoot()).to.equal(initialCommitmentRoot);
            expect(await registryV2.getIdentityCommitmentMerkleTreeSize()).to.equal(initialTreeSize);

            const commitmentIndex = await registryV2.getIdentityCommitmentIndex(commitment);
            expect(commitmentIndex).to.not.equal(ethers.MaxUint256);

            const registeredNullifier = await registryV2.nullifiers(attestationId, nullifier);
            expect(registeredNullifier).to.equal(true);
            
            const rootTimestamps = await registryV2.rootTimestamps(initialCommitmentRoot);
            expect(rootTimestamps).to.equal(registeredTimestamp);

            const implementationSlot = "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc";
            const implementationAddress = await ethers.provider.getStorage(registry.target, implementationSlot);
            expect(ethers.zeroPadValue(implementationAddress, 32))
                .to.equal(ethers.zeroPadValue(registryV2Implementation.target.toString(), 32));
        });

        it("should not allow non proxy to upgrade implementation", async() => {
            const {registryImpl, owner} = deployedActors;
            
            const PoseidonT3Factory = await ethers.getContractFactory("PoseidonT3", owner);
            const poseidonT3 = await PoseidonT3Factory.deploy();
            await poseidonT3.waitForDeployment();

            // Deploy IdentityRegistryImplV1
            const IdentityRegistryImplFactory = await ethers.getContractFactory(
                "IdentityRegistryImplV1", 
                {
                    libraries: {
                        PoseidonT3: poseidonT3.target
                    }
                },
                owner
            );

            const registryV2Implementation = await IdentityRegistryImplFactory.deploy();
            await registryV2Implementation.waitForDeployment();

            await expect(registryImpl.connect(owner).upgradeToAndCall(
                registryV2Implementation.target,
                "0x"
            )).to.be.revertedWithCustomError(registryImpl,  "UUPSUnauthorizedCallContext");
        });

        it("should not allow non owner to upgrade implementation", async () => {
            const {registry, owner, user1} = deployedActors;
            
            const PoseidonT3Factory = await ethers.getContractFactory("PoseidonT3", owner);
            const poseidonT3 = await PoseidonT3Factory.deploy();
            await poseidonT3.waitForDeployment();

            // Deploy IdentityRegistryImplV1
            const IdentityRegistryImplFactory = await ethers.getContractFactory(
                "IdentityRegistryImplV1", 
                {
                    libraries: {
                        PoseidonT3: poseidonT3.target
                    }
                },
                owner
            );

            const registryV2Implementation = await IdentityRegistryImplFactory.deploy();
            await registryV2Implementation.waitForDeployment();

            await expect(registry.connect(user1).upgradeToAndCall(
                registryV2Implementation.target,
                "0x"
            )).to.be.revertedWithCustomError(registry, "OwnableUnauthorizedAccount");
        });

        it("should not allow implementation contract to be initialized directly", async () => {
            const {owner, hub} = deployedActors;

            const PoseidonT3Factory = await ethers.getContractFactory("PoseidonT3", owner);
            const poseidonT3 = await PoseidonT3Factory.deploy();
            await poseidonT3.waitForDeployment();

            // Deploy IdentityRegistryImplV1
            const IdentityRegistryImplFactory = await ethers.getContractFactory(
                "IdentityRegistryImplV1", 
                {
                    libraries: {
                        PoseidonT3: poseidonT3.target
                    }
                },
                owner
            );

            const registryV2Implementation = await IdentityRegistryImplFactory.deploy();
            await registryV2Implementation.waitForDeployment();

            await expect(registryV2Implementation.initialize(hub.target)).to.be.revertedWithCustomError(registryV2Implementation, "InvalidInitialization");
        });

        it("should not allow direct calls to implementation contract", async () => {
            const {owner} = deployedActors;
            
            const PoseidonT3Factory = await ethers.getContractFactory("PoseidonT3", owner);
            const poseidonT3 = await PoseidonT3Factory.deploy();
            await poseidonT3.waitForDeployment();

            // Deploy IdentityRegistryImplV1
            const IdentityRegistryImplFactory = await ethers.getContractFactory(
                "IdentityRegistryImplV1", 
                {
                    libraries: {
                        PoseidonT3: poseidonT3.target
                    }
                },
                owner
            );

            const registryV2Implementation = await IdentityRegistryImplFactory.deploy();
            await registryV2Implementation.waitForDeployment();

            await expect(
                registryV2Implementation.updateCscaRoot(generateRandomFieldElement())
            ).to.be.revertedWithCustomError(registryV2Implementation, "UUPSUnauthorizedCallContext");
        });
    });
});