import { expect } from "chai";
import { deploySystemFixtures } from "../utils/deployment";
import { DeployedActors } from "../utils/types";
import { ethers } from "hardhat";
import { RegisterVerifierId, DscVerifierId } from "../../../common/src/constants/constants";

describe("Unit Tests for IdentityVerificationHub", () => {

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
        it("should initialize hub with correct parameters", async () => {
            const {hub, registry, vcAndDisclose, register, dsc} = deployedActors;
            
            // Check initial state
            expect(await hub.registry()).to.equal(registry.target);
            expect(await hub.vcAndDiscloseCircuitVerifier()).to.equal(vcAndDisclose.target);

            const registerId = RegisterVerifierId.register_sha256_sha256_sha256_rsa_65537_4096;
            const dscId = DscVerifierId.dsc_rsa_sha256_65537_4096;
            expect(await hub.sigTypeToRegisterCircuitVerifiers(registerId)).to.equal(register.target);
            expect(await hub.sigTypeToDscCircuitVerifiers(dscId)).to.equal(dsc.target);

            const filter = hub.filters.HubInitialized;
            const events = await hub.queryFilter(filter);
            expect(events.length).to.equal(1);
            const event = events[0];
            expect(event.args.registry).to.equal(registry.target);
            expect(event.args.vcAndDiscloseCircuitVerifier).to.equal(vcAndDisclose.target);
            expect(event.args.registerCircuitVerifierIds).to.deep.equal([registerId]);
            expect(event.args.registerCircuitVerifiers).to.deep.equal([register.target]);
            expect(event.args.dscCircuitVerifierIds).to.deep.equal([dscId]);
            expect(event.args.dscCircuitVerifiers).to.deep.equal([dsc.target]);
        });

        it("should not allow direct initialization of hub implementation", async () => {
            const {owner, registry, vcAndDisclose} = deployedActors;
            
            const HubFactory = await ethers.getContractFactory("IdentityVerificationHubImplV1", owner);
            const hubImpl = await HubFactory.deploy();

            await expect(
                hubImpl.initialize(
                    registry.target,
                    vcAndDisclose.target,
                    [],
                    [],
                    [],
                    []
                )
            ).to.be.revertedWithCustomError(hubImpl, "InvalidInitialization");
        });

        it("should revert when register circuit verifier arrays length mismatch", async () => {
            const {owner, registry, vcAndDisclose} = deployedActors;
            
            const HubFactory = await ethers.getContractFactory("IdentityVerificationHubImplV1", owner);
            const hubImpl = await HubFactory.deploy();
            await hubImpl.waitForDeployment();

            const initializeData = hubImpl.interface.encodeFunctionData("initialize", [
                registry.target,
                vcAndDisclose.target,
                [1],
                [], 
                [],
                []
            ]);
            const hubProxyFactory = await ethers.getContractFactory("IdentityVerificationHub", owner);
            
            await expect(
                hubProxyFactory.deploy(hubImpl.target, initializeData)
            ).to.be.revertedWithCustomError(hubImpl, "LENGTH_MISMATCH");
        });

        it("should revert when DSC circuit verifier arrays length mismatch", async () => {
            const {owner, registry, vcAndDisclose} = deployedActors;
            
            const HubFactory = await ethers.getContractFactory("IdentityVerificationHubImplV1", owner);
            const hubImpl = await HubFactory.deploy();
            await hubImpl.waitForDeployment();

            const initializeData = hubImpl.interface.encodeFunctionData("initialize", [
                registry.target,
                vcAndDisclose.target,
                [],
                [],
                [1],
                [] 
            ]);
            const hubProxyFactory = await ethers.getContractFactory("IdentityVerificationHub", owner);
            
            await expect(
                hubProxyFactory.deploy(hubImpl.target, initializeData)
            ).to.be.revertedWithCustomError(hubImpl, "LENGTH_MISMATCH");
        });

        it("should not allow initialization after initialized", async () => {
            const { hub, registry, vcAndDisclose } = deployedActors;
            
            await expect(
                hub.initialize(
                    registry.target,
                    vcAndDisclose.target,
                    [],
                    [],
                    [],
                    []
                )
            ).to.be.revertedWithCustomError(hub, "InvalidInitialization");
        });
    });

    describe("Update functions", () => {
        it("should update registry address", async () => {
            const { hub, user1 } = deployedActors;
            const newRegistryAddress = await user1.getAddress();

            await expect(hub.updateRegistry(newRegistryAddress))
                .to.emit(hub, "RegistryUpdated")
                .withArgs(newRegistryAddress);

            expect(await hub.registry()).to.equal(newRegistryAddress);
        });

        it("should not update registry address if caller is not owner", async () => {
            const { hub, user1 } = deployedActors;
            const newRegistryAddress = await user1.getAddress();

            await expect(hub.connect(user1).updateRegistry(newRegistryAddress)).to.be.revertedWithCustomError(hub, "OwnableUnauthorizedAccount");
        });

        it ("should not update registry address if caller is not proxy", async () => {
            const { hubImpl, user1 } = deployedActors;
            const newRegistryAddress = await user1.getAddress();

            await expect(hubImpl.updateRegistry(newRegistryAddress)).to.be.revertedWithCustomError(hubImpl, "UUPSUnauthorizedCallContext");
        });

        it("should update vc and disclose circuit verifier", async () => {
            const { hub, user1 } = deployedActors;
            const newVerifierAddress = await user1.getAddress();

            await expect(hub.updateVcAndDiscloseCircuit(newVerifierAddress))
                .to.emit(hub, "VcAndDiscloseCircuitUpdated")
                .withArgs(newVerifierAddress);

            expect(await hub.vcAndDiscloseCircuitVerifier()).to.equal(newVerifierAddress);
        });

        it("should not update vc and disclose circuit verifier if caller is not owner", async () => {   
            const { hub, user1 } = deployedActors;
            const newVerifierAddress = await user1.getAddress();

            await expect(hub.connect(user1).updateVcAndDiscloseCircuit(newVerifierAddress)).to.be.revertedWithCustomError(hub, "OwnableUnauthorizedAccount");
        });

        it("should not update vc and disclose circuit verifier if caller is not proxy", async () => {
            const { hubImpl, user1 } = deployedActors;
            const newVerifierAddress = await user1.getAddress();

            await expect(hubImpl.updateVcAndDiscloseCircuit(newVerifierAddress)).to.be.revertedWithCustomError(hubImpl, "UUPSUnauthorizedCallContext");
        });

        it("should update register circuit verifier", async () => {
            const { hub, user1 } = deployedActors;
            const verifierId = RegisterVerifierId.register_sha256_sha256_sha256_rsa_65537_4096;
            const newVerifierAddress = await user1.getAddress();

            await expect(hub.updateRegisterCircuitVerifier(verifierId, newVerifierAddress))
                .to.emit(hub, "RegisterCircuitVerifierUpdated")
                .withArgs(verifierId, newVerifierAddress);

            expect(await hub.sigTypeToRegisterCircuitVerifiers(verifierId)).to.equal(newVerifierAddress);
        });

        it("should not update register circuit verifier if caller is not owner", async () => {
            const { hub, user1 } = deployedActors;
            const verifierId = RegisterVerifierId.register_sha256_sha256_sha256_rsa_65537_4096;
            const newVerifierAddress = await user1.getAddress();

            await expect(hub.connect(user1).updateRegisterCircuitVerifier(verifierId, newVerifierAddress)).to.be.revertedWithCustomError(hub, "OwnableUnauthorizedAccount");
        });

        it("should not update register circuit verifier if caller is not proxy", async () => {
            const { hubImpl, user1 } = deployedActors;
            const verifierId = RegisterVerifierId.register_sha256_sha256_sha256_rsa_65537_4096;
            const newVerifierAddress = await user1.getAddress();

            await expect(hubImpl.updateRegisterCircuitVerifier(verifierId, newVerifierAddress)).to.be.revertedWithCustomError(hubImpl, "UUPSUnauthorizedCallContext");
        });

        it("should update DSC verifier", async () => {
            const { hub, user1 } = deployedActors;
            const verifierId = DscVerifierId.dsc_rsa_sha256_65537_4096;
            const newVerifierAddress = await user1.getAddress();

            await expect(hub.updateDscVerifier(verifierId, newVerifierAddress))
                .to.emit(hub, "DscCircuitVerifierUpdated")
                .withArgs(verifierId, newVerifierAddress);

            expect(await hub.sigTypeToDscCircuitVerifiers(verifierId)).to.equal(newVerifierAddress);
        });

        it("should not update DSC verifier if caller is not owner", async () => {
            const { hub, user1 } = deployedActors;
            const verifierId = DscVerifierId.dsc_rsa_sha256_65537_4096;
            const newVerifierAddress = await user1.getAddress();

            await expect(hub.connect(user1).updateDscVerifier(verifierId, newVerifierAddress)).to.be.revertedWithCustomError(hub, "OwnableUnauthorizedAccount");
        });

        it("should not update DSC verifier if caller is not proxy", async () => {
            const { hubImpl, user1 } = deployedActors;
            const verifierId = DscVerifierId.dsc_rsa_sha256_65537_4096;
            const newVerifierAddress = await user1.getAddress();

            await expect(hubImpl.updateDscVerifier(verifierId, newVerifierAddress)).to.be.revertedWithCustomError(hubImpl, "UUPSUnauthorizedCallContext");
        });

        it("should batch update register circuit verifiers", async () => {
            const { hub, user1 } = deployedActors;
            const verifierIds = [1, 2];
            const newVerifierAddresses = [await user1.getAddress(), await user1.getAddress()];

            await expect(hub.batchUpdateRegisterCircuitVerifiers(verifierIds, newVerifierAddresses))
                .to.emit(hub, "RegisterCircuitVerifierUpdated")
                .withArgs(verifierIds[0], newVerifierAddresses[0])
                .to.emit(hub, "RegisterCircuitVerifierUpdated")
                .withArgs(verifierIds[1], newVerifierAddresses[1]);
            
            for (let i = 0; i < verifierIds.length; i++) {
                expect(await hub.sigTypeToRegisterCircuitVerifiers(verifierIds[i]))
                    .to.equal(newVerifierAddresses[i]);
            }
        });

        it("should not batch update register circuit verifiers if caller is not owner", async () => {
            const { hub, user1 } = deployedActors;
            const verifierIds = [1, 2];
            const newVerifierAddresses = [await user1.getAddress(), await user1.getAddress()];

            await expect(hub.connect(user1).batchUpdateRegisterCircuitVerifiers(verifierIds, newVerifierAddresses)).to.be.revertedWithCustomError(hub, "OwnableUnauthorizedAccount");
        });

        it("should not batch update register circuit verifiers if caller is not proxy", async () => {
            const { hubImpl, user1 } = deployedActors;
            const verifierIds = [1, 2];
            const newVerifierAddresses = [await user1.getAddress(), await user1.getAddress()];

            await expect(hubImpl.batchUpdateRegisterCircuitVerifiers(verifierIds, newVerifierAddresses))
                .to.be.revertedWithCustomError(hubImpl, "UUPSUnauthorizedCallContext");
        });

        it("should not batch update register verifiers if length is not the same", async () => {
            const { hub, user1 } = deployedActors;
            const verifierIds = [1];
            const newVerifierAddresses = [await user1.getAddress(), await user1.getAddress()];

            await expect(
                hub.batchUpdateRegisterCircuitVerifiers(verifierIds, newVerifierAddresses)
            ).to.be.revertedWithCustomError(hub, "LENGTH_MISMATCH");
        });

        it("should batch update DSC circuit verifiers", async () => {
            const { hub, user1 } = deployedActors;
            const verifierIds = [1, 2];
            const newVerifierAddresses = [await user1.getAddress(), await user1.getAddress()];

            await expect(hub.batchUpdateDscCircuitVerifiers(verifierIds, newVerifierAddresses))
                .to.emit(hub, "DscCircuitVerifierUpdated")
                .withArgs(verifierIds[0], newVerifierAddresses[0])
                .to.emit(hub, "DscCircuitVerifierUpdated")
                .withArgs(verifierIds[1], newVerifierAddresses[1]);
            
            for (let i = 0; i < verifierIds.length; i++) {
                expect(await hub.sigTypeToDscCircuitVerifiers(verifierIds[i]))
                    .to.equal(newVerifierAddresses[i]);
            }
        });

        it("should not batch update DSC circuit verifiers if caller is not owner", async () => {
            const { hub, user1 } = deployedActors;
            const verifierIds = [1, 2];
            const newVerifierAddresses = [await user1.getAddress(), await user1.getAddress()];

            await expect(hub.connect(user1).batchUpdateDscCircuitVerifiers(verifierIds, newVerifierAddresses)).to.be.revertedWithCustomError(hub, "OwnableUnauthorizedAccount");
        });

        it("should not batch update DSC circuit verifiers if caller is not proxy", async () => {
            const { hubImpl, user1 } = deployedActors;
            const verifierIds = [1, 2];
            const newVerifierAddresses = [await user1.getAddress(), await user1.getAddress()];

            await expect(hubImpl.batchUpdateDscCircuitVerifiers(verifierIds, newVerifierAddresses))
                .to.be.revertedWithCustomError(hubImpl, "UUPSUnauthorizedCallContext");
        });

        it("should not batch update dsc verifiers if length is not the same", async () => {
            const { hub, user1 } = deployedActors;
            const verifierIds = [1];
            const newVerifierAddresses = [await user1.getAddress(), await user1.getAddress()];

            await expect(
                hub.batchUpdateDscCircuitVerifiers(verifierIds, newVerifierAddresses)
            ).to.be.revertedWithCustomError(hub, "LENGTH_MISMATCH");
        });
    });

    describe("View functions", () => {
        it("should return correct registry address", async () => {
            const { hub, registry } = deployedActors;
            expect(await hub.registry()).to.equal(registry.target);
        });

        it("should not return when view function is called by non-proxy", async () => {
            const { hubImpl } = deployedActors;
            await expect(hubImpl.registry()).to.be.revertedWithCustomError(hubImpl, "UUPSUnauthorizedCallContext");
        });

        it("should return correct vcAndDiscloseCircuitVerifier address", async () => {
            const { hub, vcAndDisclose } = deployedActors;
            expect(await hub.vcAndDiscloseCircuitVerifier()).to.equal(vcAndDisclose.target);
        });

        it("should not return when view function is called by non-proxy", async () => {
            const { hubImpl } = deployedActors;
            await expect(hubImpl.vcAndDiscloseCircuitVerifier()).to.be.revertedWithCustomError(hubImpl, "UUPSUnauthorizedCallContext");
        });

        it("should return correct register circuit verifier address", async () => {
            const { hub, register } = deployedActors;
            const verifierId = RegisterVerifierId.register_sha256_sha256_sha256_rsa_65537_4096;
            expect(await hub.sigTypeToRegisterCircuitVerifiers(verifierId)).to.equal(register.target);
        });

        it("should not return when view function is called by non-proxy", async () => {
            const { hubImpl } = deployedActors;
            await expect(hubImpl.sigTypeToRegisterCircuitVerifiers(1)).to.be.revertedWithCustomError(hubImpl, "UUPSUnauthorizedCallContext");
        });

        it("should return correct dsc circuit verifier address", async () => {
            const { hub, dsc } = deployedActors;
            const verifierId = DscVerifierId.dsc_rsa_sha256_65537_4096;
            expect(await hub.sigTypeToDscCircuitVerifiers(verifierId)).to.equal(dsc.target);
        });

        it("should not return when view function is called by non-proxy", async () => {
            const { hubImpl } = deployedActors;
            await expect(hubImpl.sigTypeToDscCircuitVerifiers(1)).to.be.revertedWithCustomError(hubImpl, "UUPSUnauthorizedCallContext");
        });

    });

    describe("Upgradeabilitiy", () => {

        it("should preserve state after upgrade", async () => {
            const {hub, owner} = deployedActors;

            const registryAddressBefore = await hub.registry();
            const vcAndDiscloseCircuitVerifierBefore = await hub.vcAndDiscloseCircuitVerifier();
            const registerCircuitVerifierIdsBefore = await hub.sigTypeToRegisterCircuitVerifiers(
                RegisterVerifierId.register_sha256_sha256_sha256_rsa_65537_4096
            );
            const dscCircuitVerifierIdsBefore = await hub.sigTypeToDscCircuitVerifiers(
                DscVerifierId.dsc_rsa_sha256_65537_4096
            );
            
            const HubV2Factory = await ethers.getContractFactory("IdentityVerificationHubImplV1", owner);
            const hubV2Implementation = await HubV2Factory.deploy();
            await hubV2Implementation.waitForDeployment();

            const hubAsImpl = await ethers.getContractAt(
                "IdentityVerificationHubImplV1",
                hub.target
            );

            await hubAsImpl.connect(owner).upgradeToAndCall(
                hubV2Implementation.target,
                "0x"
            );

            const hubV2 = await ethers.getContractAt("IdentityVerificationHubImplV1", hub.target);
            const registryAddressAfter = await hubV2.registry();
            expect(registryAddressAfter).to.equal(registryAddressBefore);
            expect(await hubV2.vcAndDiscloseCircuitVerifier()).to.equal(vcAndDiscloseCircuitVerifierBefore);
            expect(await hubV2.sigTypeToRegisterCircuitVerifiers(
                RegisterVerifierId.register_sha256_sha256_sha256_rsa_65537_4096
            )).to.equal(registerCircuitVerifierIdsBefore);
            expect(await hubV2.sigTypeToDscCircuitVerifiers(
                DscVerifierId.dsc_rsa_sha256_65537_4096
            )).to.equal(dscCircuitVerifierIdsBefore);

            const implementationSlot = "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc";
            const implementationAddress = await ethers.provider.getStorage(hub.target, implementationSlot);
            expect(ethers.zeroPadValue(implementationAddress, 32))
                .to.equal(ethers.zeroPadValue(hubV2Implementation.target.toString(), 32));
        });

        it("should not allow non-proxy to upgrade implementation", async() => {
            const {hub, hubImpl, owner, user1} = deployedActors;
            
            const HubV2Factory = await ethers.getContractFactory("IdentityVerificationHubImplV1", owner);
            const hubV2Implementation = await HubV2Factory.deploy();
            await hubV2Implementation.waitForDeployment();

            const hubAsImpl = await ethers.getContractAt(
                "IdentityVerificationHubImplV1",
                hub.target
            );

            await expect(
                hubImpl.connect(owner).upgradeToAndCall(
                    hubV2Implementation.target,
                    "0x"
                )
            ).to.be.revertedWithCustomError(hubAsImpl, "UUPSUnauthorizedCallContext");
        });

        it("should not allow non-owner to upgrade implementation", async () => {
            const {hub, owner, user1} = deployedActors;
            
            const HubV2Factory = await ethers.getContractFactory("IdentityVerificationHubImplV1", owner);
            const hubV2Implementation = await HubV2Factory.deploy();
            await hubV2Implementation.waitForDeployment();

            const hubAsImpl = await ethers.getContractAt(
                "IdentityVerificationHubImplV1",
                hub.target
            );

            await expect(
                hubAsImpl.connect(user1).upgradeToAndCall(
                    hubV2Implementation.target,
                    "0x"
                )
            ).to.be.revertedWithCustomError(hubAsImpl, "OwnableUnauthorizedAccount");
        });

        it("should not allow implementation contract to be initialized directly", async () => {
            const {hub, owner} = deployedActors;
            
            const HubV2Factory = await ethers.getContractFactory("IdentityVerificationHubImplV1", owner);
            const hubV2Implementation = await HubV2Factory.deploy();
            await hubV2Implementation.waitForDeployment();

            await expect(
                hubV2Implementation.initialize(
                    ethers.ZeroAddress,
                    ethers.ZeroAddress,
                    [],
                    [],
                    [],
                    []
                )
            ).to.be.revertedWithCustomError(hub, "InvalidInitialization");
        });

        it("should not allow direct calls to implementation contract", async () => {
            const {hub, owner} = deployedActors;
            
            const HubV2Factory = await ethers.getContractFactory("IdentityVerificationHubImplV1", owner);
            const hubV2Implementation = await HubV2Factory.deploy();
            await hubV2Implementation.waitForDeployment();

            await expect(
                hubV2Implementation.updateRegistry(ethers.ZeroAddress)
            ).to.be.revertedWithCustomError(hubV2Implementation, "UUPSUnauthorizedCallContext");
        });
    });
});