import { expect } from "chai";
import { deploySystemFixtures } from "../utils/deployment";
import { DeployedActors } from "../utils/types";
import { ethers } from "hardhat";
import { ZeroAddress } from "ethers";
import { generateRandomFieldElement } from "../utils/utils";

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
            // Check initial state
            expect(await registry.hub()).to.equal(hub.target);
            
            // Check event emission
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
    });

    describe("Update functions", () => {
        it("should update hub address", async () => {
            const { registry, owner, user1 } = deployedActors;
            const newHubAddress = await user1.getAddress();

            // Update hub address and check event emission
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

            // Update OFAC root and check event emission
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

            // Update CSCA root and check event emission
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
            const attestationId = ethers.toBeHex(generateRandomFieldElement());
            const nullifier = ethers.toBeHex(generateRandomFieldElement());
            const commitment = ethers.toBeHex(generateRandomFieldElement());

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
            const attestationId = ethers.toBeHex(generateRandomFieldElement());
            const nullifier = ethers.toBeHex(generateRandomFieldElement());
            const commitment = ethers.toBeHex(generateRandomFieldElement());

            await expect(registry.connect(user1).devAddIdentityCommitment(attestationId, nullifier, commitment)).to.be.revertedWithCustomError(registry, "OwnableUnauthorizedAccount");
        });

        it("should not add commitment if caller is not proxy", async () => {
            const { registryImpl, user1 } = deployedActors;
            const attestationId = ethers.toBeHex(generateRandomFieldElement());
            const nullifier = ethers.toBeHex(generateRandomFieldElement());
            const commitment = ethers.toBeHex(generateRandomFieldElement());

            await expect(registryImpl.connect(user1).devAddIdentityCommitment(attestationId, nullifier, commitment)).to.be.revertedWithCustomError(registryImpl, "UUPSUnauthorizedCallContext");
        });

        it("should be able to update commitment by owner", async () => {
            const { registry } = deployedActors;
            const attestationId = ethers.toBeHex(generateRandomFieldElement());
            const nullifier = ethers.toBeHex(generateRandomFieldElement());
            const commitment = ethers.toBeHex(generateRandomFieldElement());
            await registry.devAddIdentityCommitment(attestationId, nullifier, commitment);
            const newCommitment = ethers.toBeHex(generateRandomFieldElement());
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
            const attestationId = ethers.toBeHex(generateRandomFieldElement());
            const nullifier = ethers.toBeHex(generateRandomFieldElement());
            const commitment = ethers.toBeHex(generateRandomFieldElement());
            await registry.devAddIdentityCommitment(attestationId, nullifier, commitment);
            const newCommitment = ethers.toBeHex(generateRandomFieldElement());
            await expect(registry.connect(user1).devUpdateCommitment(commitment, newCommitment, [])).to.be.revertedWithCustomError(registry, "OwnableUnauthorizedAccount");
        });

        it("should not update commitment if caller is not proxy", async () => {
            const { registry, registryImpl, user1 } = deployedActors;
            const attestationId = ethers.toBeHex(generateRandomFieldElement());
            const nullifier = ethers.toBeHex(generateRandomFieldElement());
            const commitment = ethers.toBeHex(generateRandomFieldElement());
            await registry.devAddIdentityCommitment(attestationId, nullifier, commitment);
            const newCommitment = ethers.toBeHex(generateRandomFieldElement());
            await expect(registryImpl.connect(user1).devUpdateCommitment(commitment, newCommitment, [])).to.be.revertedWithCustomError(registryImpl, "UUPSUnauthorizedCallContext");
        });

        it("able to remove commitment by owner", async () => {
            const { registry, owner, user1 } = deployedActors;
            const attestationId = ethers.toBeHex(generateRandomFieldElement());
            const nullifier = ethers.toBeHex(generateRandomFieldElement());
            const commitment = ethers.toBeHex(generateRandomFieldElement());
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
            const attestationId = ethers.toBeHex(generateRandomFieldElement());
            const nullifier = ethers.toBeHex(generateRandomFieldElement());
            const commitment = ethers.toBeHex(generateRandomFieldElement());
            await registry.devAddIdentityCommitment(attestationId, nullifier, commitment);
            await expect(registry.connect(user1).devRemoveCommitment(commitment, [])).to.be.revertedWithCustomError(registry, "OwnableUnauthorizedAccount");
        });

        it("should not remove commitment if caller is not proxy", async () => {
            const { registry, registryImpl, user1 } = deployedActors;
            const attestationId = ethers.toBeHex(generateRandomFieldElement());
            const nullifier = ethers.toBeHex(generateRandomFieldElement());
            const commitment = ethers.toBeHex(generateRandomFieldElement());
            await registry.devAddIdentityCommitment(attestationId, nullifier, commitment);
            await expect(registryImpl.connect(user1).devRemoveCommitment(commitment, [])).to.be.revertedWithCustomError(registryImpl, "UUPSUnauthorizedCallContext");
        });

        it("able to remove nullifier by owner", async () => {
            const { registry, owner, user1 } = deployedActors;
            const attestationId = ethers.toBeHex(generateRandomFieldElement());
            const nullifier = ethers.toBeHex(generateRandomFieldElement());

            const tx = await registry.devRemoveNullifier(attestationId, nullifier);
            const receipt = await tx.wait();
            const blockTimestamp = (await ethers.provider.getBlock("latest"))!.timestamp;
            const event = receipt?.logs.find(
                log => log.topics[0] === registry.interface.getEvent("DevNullifierRemoved").topicHash
            );
            const eventArgs = event ? registry.interface.decodeEventLog(
                "DevNullifierRemoved",
                event.data,
                event.topics
            ) : null;

            const nullifierCheck = await registry.nullifiers(attestationId, nullifier);
            expect(eventArgs?.nullifier).to.equal(nullifier);
            expect(eventArgs?.timestamp).to.equal(blockTimestamp);
            expect(nullifierCheck).to.equal(false);
        });

        it("should not remove nullifier if caller is not owner", async () => {
            const { registry, user1 } = deployedActors;
            const attestationId = ethers.toBeHex(generateRandomFieldElement());
            const nullifier = ethers.toBeHex(generateRandomFieldElement());
            await expect(registry.connect(user1).devRemoveNullifier(attestationId, nullifier)).to.be.revertedWithCustomError(registry, "OwnableUnauthorizedAccount");
        });

        it("should not remove nullifier if caller is not proxy", async () => {
            const { registryImpl, user1 } = deployedActors;
            const attestationId = ethers.toBeHex(generateRandomFieldElement());
            const nullifier = ethers.toBeHex(generateRandomFieldElement());
            await expect(registryImpl.connect(user1).devRemoveNullifier(attestationId, nullifier)).to.be.revertedWithCustomError(registryImpl, "UUPSUnauthorizedCallContext");
        });
    });

    describe("Upgradeability", () => {
        it("should preserve registry state after upgrade", async () => {
            const {registry, owner, user1} = deployedActors;

            const initialHub = await registry.hub();
            const initialCscaRoot = await registry.getCscaRoot();
            const initialOfacRoot = await registry.getOfacRoot();

            const attestationId = ethers.hexlify(ethers.concat([new Uint8Array(16), ethers.randomBytes(16)]));
            const nullifier = ethers.hexlify(ethers.concat([new Uint8Array(16), ethers.randomBytes(16)]));
            const commitment = ethers.hexlify(ethers.concat([new Uint8Array(16), ethers.randomBytes(16)]));
            const tx = await registry.devAddIdentityCommitment(attestationId, nullifier, commitment);
            const receipt = await tx.wait() as TransactionReceipt;
            const registeredTimestamp = (await ethers.provider.getBlock(receipt.blockNumber))!.timestamp;

            const initialCommitmentRoot = await registry.getIdentityCommitmentMerkleRoot();
            const initialTreeSize = await registry.getIdentityCommitmentMerkleTreeSize();

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
            const {registry, owner} = deployedActors;
            
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

            // Try to call _authorizeUpgrade directly on the implementation contract
            await expect(
                registryV2Implementation.updateCscaRoot(generateRandomFieldElement())
            ).to.be.revertedWithCustomError(registryV2Implementation, "UUPSUnauthorizedCallContext");
        });
    });
});