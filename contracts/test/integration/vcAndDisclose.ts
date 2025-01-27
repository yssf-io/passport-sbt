import { expect } from "chai";
import { deploySystemFixtures } from "../utils/deployment";
import { DeployedActors } from "../utils/types";
import { ethers } from "hardhat";
import { generateDscSecret } from "../../../common/src/utils/csca";
import { CIRCUIT_CONSTANTS } from "../utils/constants";
import { RegisterVerifierId, DscVerifierId } from "../../../common/src/constants/constants";
import { PassportProof, VcAndDiscloseHubProof } from "../utils/types";
import { ATTESTATION_ID } from "../utils/constants";
import { generateRegisterProof, generateDscProof, generateVcAndDiscloseProof } from "../utils/generateProof";
import { LeanIMT } from "@openpassport/zk-kit-lean-imt";
import { poseidon2 } from "poseidon-lite";
import { generateCommitment } from "../../../common/src/utils/passports/passport";
import { BigNumberish } from "ethers";

describe("VC and Disclose", () => {
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

    describe("Verify VC and Disclose", () => {
        it("should verify and get result successfully", async () => {
            const {hub, registry, owner, user1, mockPassport} = deployedActors;

            // First register a passport commitment
            const registerSecret = "1234567890";
            const dscSecret = generateDscSecret();

            // Register the commitment first
            const registerProof = await generateRegisterProof(
                registerSecret, 
                dscSecret, 
                mockPassport
            );
            const dscProof = await generateDscProof(
                dscSecret, 
                mockPassport.dsc, 
                1664
            );

            const passportProof: PassportProof = {
                registerCircuitVerifierId: RegisterVerifierId.register_sha256_sha256_sha256_rsa_65537_4096,
                dscCircuitVerifierId: DscVerifierId.dsc_rsa_sha256_65537_4096,
                registerCircuitProof: registerProof,
                dscCircuitProof: dscProof
            };

            await hub.verifyAndRegisterPassportCommitment(passportProof);

            // Set up IMT for the VC and Disclose proof
            const commitment = generateCommitment(registerSecret, ATTESTATION_ID.E_PASSPORT, mockPassport);
            const hashFunction = (a: bigint, b: bigint) => poseidon2([a, b]);
            const imt = new LeanIMT<bigint>(hashFunction);
            await imt.insert(BigInt(commitment));
    
            // Generate VC and Disclose proof
            const vcAndDiscloseProof = await generateVcAndDiscloseProof(
                registerSecret,
                BigInt(ATTESTATION_ID.E_PASSPORT).toString(),
                mockPassport,
                "test-scope",
                new Array(88).fill("1"),
                "1",
                imt,
                "20",
            );
            const smtRoot = await registry.getOfacRoot();

            // Verify and get result
            const result = await hub.verifyVcAndDiscloseAndGetResult(vcAndDiscloseProof);

            // // Verify the returned results
            expect(result.revealedDataPacked).to.have.lengthOf(3);
            expect(result.nullifier).to.equal(vcAndDiscloseProof.pubSignals[CIRCUIT_CONSTANTS.VC_AND_DISCLOSE_NULLIFIER_INDEX]);
            expect(result.attestationId).to.equal(vcAndDiscloseProof.pubSignals[CIRCUIT_CONSTANTS.VC_AND_DISCLOSE_ATTESTATION_ID_INDEX]);
            expect(result.userIdentifier).to.equal(vcAndDiscloseProof.pubSignals[CIRCUIT_CONSTANTS.VC_AND_DISCLOSE_USER_IDENTIFIER_INDEX]);
            expect(result.scope).to.equal(vcAndDiscloseProof.pubSignals[CIRCUIT_CONSTANTS.VC_AND_DISCLOSE_SCOPE_INDEX]);
        });

        it("should fail with invalid identity commitment root", async () => {
            const {hub, registry, owner, user1, mockPassport} = deployedActors;

            const registerSecret = "1234567890";
            const dscSecret = generateDscSecret();

            // Register the commitment first
            const registerProof = await generateRegisterProof(
                registerSecret, 
                dscSecret, 
                mockPassport
            );
            const dscProof = await generateDscProof(
                dscSecret, 
                mockPassport.dsc, 
                1664
            );

            const passportProof: PassportProof = {
                registerCircuitVerifierId: RegisterVerifierId.register_sha256_sha256_sha256_rsa_65537_4096,
                dscCircuitVerifierId: DscVerifierId.dsc_rsa_sha256_65537_4096,
                registerCircuitProof: registerProof,
                dscCircuitProof: dscProof
            };

            await hub.verifyAndRegisterPassportCommitment(passportProof);

            // Generate proof without registering commitment
            const imt = new LeanIMT<bigint>((a: bigint, b: bigint) => poseidon2([a, b]));
            const commitment = generateCommitment(registerSecret, ATTESTATION_ID.E_PASSPORT, mockPassport);
            await imt.insert(BigInt(commitment));
            
            const vcAndDiscloseProof = await generateVcAndDiscloseProof(
                registerSecret,
                BigInt(ATTESTATION_ID.E_PASSPORT).toString(),
                mockPassport,
                "test-scope",
                new Array(88).fill("1"),
                "1",
                imt,
                "20",
            );
            vcAndDiscloseProof.pubSignals[CIRCUIT_CONSTANTS.VC_AND_DISCLOSE_MERKLE_ROOT_INDEX] = "123456789";

            await expect(
                hub.verifyVcAndDiscloseAndGetResult(vcAndDiscloseProof)
            ).to.be.revertedWithCustomError(hub, "INVALID_IDENTITY_COMMITMENT_ROOT");
        });

        it("should fail with invalid current date (+ 1 day)", async () => {
            
            const {hub, registry, owner, user1, mockPassport} = deployedActors;

            const registerSecret = "1234567890";
            const dscSecret = generateDscSecret();

            // Register the commitment first
            const registerProof = await generateRegisterProof(
                registerSecret, 
                dscSecret, 
                mockPassport
            );
            const dscProof = await generateDscProof(
                dscSecret, 
                mockPassport.dsc, 
                1664
            );

            const passportProof: PassportProof = {
                registerCircuitVerifierId: RegisterVerifierId.register_sha256_sha256_sha256_rsa_65537_4096,
                dscCircuitVerifierId: DscVerifierId.dsc_rsa_sha256_65537_4096,
                registerCircuitProof: registerProof,
                dscCircuitProof: dscProof
            };

            await hub.verifyAndRegisterPassportCommitment(passportProof);

            // Generate proof without registering commitment
            const commitment = generateCommitment(registerSecret, ATTESTATION_ID.E_PASSPORT, mockPassport);
            const hashFunction = (a: bigint, b: bigint) => poseidon2([a, b]);
            const imt = new LeanIMT<bigint>(hashFunction);
            await imt.insert(BigInt(commitment));
            
            const vcAndDiscloseProof = await generateVcAndDiscloseProof(
                registerSecret,
                BigInt(ATTESTATION_ID.E_PASSPORT).toString(),
                mockPassport,
                "test-scope",
                new Array(88).fill("1"),
                "1",
                imt,
                "20",
            );

            const currentBlock = await ethers.provider.getBlock('latest');
            const oneDayAfter = (currentBlock!.timestamp - 24 * 60 * 60 + 1);
            
            // Convert timestamp to 6 digits YYMMDD format
            const date = new Date(oneDayAfter * 1000);
            const dateComponents = [
                Math.floor((date.getUTCFullYear() % 100) / 10),
                date.getUTCFullYear() % 10,                    
                Math.floor((date.getUTCMonth() + 1) / 10),     
                (date.getUTCMonth() + 1) % 10,                 
                Math.floor(date.getUTCDate() / 10),            
                date.getUTCDate() % 10                         
            ];

            for (let i = 0; i < 6; i++) {
                vcAndDiscloseProof.pubSignals[CIRCUIT_CONSTANTS.VC_AND_DISCLOSE_CURRENT_DATE_INDEX + i] = dateComponents[i].toString();
            }

            await expect(
                hub.verifyVcAndDiscloseAndGetResult(vcAndDiscloseProof)
            ).to.be.revertedWithCustomError(hub, "CURRENT_DATE_NOT_IN_VALID_RANGE");
        });

        it("should fail with invalid current date (- 1 day)", async () => {
            
            const {hub, registry, owner, user1, mockPassport} = deployedActors;

            const registerSecret = "1234567890";
            const dscSecret = generateDscSecret();

            // Register the commitment first
            const registerProof = await generateRegisterProof(
                registerSecret, 
                dscSecret, 
                mockPassport
            );
            const dscProof = await generateDscProof(
                dscSecret, 
                mockPassport.dsc, 
                1664
            );

            const passportProof: PassportProof = {
                registerCircuitVerifierId: RegisterVerifierId.register_sha256_sha256_sha256_rsa_65537_4096,
                dscCircuitVerifierId: DscVerifierId.dsc_rsa_sha256_65537_4096,
                registerCircuitProof: registerProof,
                dscCircuitProof: dscProof
            };

            await hub.verifyAndRegisterPassportCommitment(passportProof);

            // Generate proof without registering commitment
            const commitment = generateCommitment(registerSecret, ATTESTATION_ID.E_PASSPORT, mockPassport);
            const hashFunction = (a: bigint, b: bigint) => poseidon2([a, b]);
            const imt = new LeanIMT<bigint>(hashFunction);
            await imt.insert(BigInt(commitment));
            
            const vcAndDiscloseProof = await generateVcAndDiscloseProof(
                registerSecret,
                BigInt(ATTESTATION_ID.E_PASSPORT).toString(),
                mockPassport,
                "test-scope",
                new Array(88).fill("1"),
                "1",
                imt,
                "20",
            );

            const currentBlock = await ethers.provider.getBlock('latest');
            const oneDayBefore = (currentBlock!.timestamp - 24 * 60 * 60 - 1);
            
            // Convert timestamp to 6 digits YYMMDD format
            const date = new Date(oneDayBefore * 1000);
            const dateComponents = [
                Math.floor((date.getUTCFullYear() % 100) / 10),
                date.getUTCFullYear() % 10,                    
                Math.floor((date.getUTCMonth() + 1) / 10),     
                (date.getUTCMonth() + 1) % 10,                 
                Math.floor(date.getUTCDate() / 10),            
                date.getUTCDate() % 10                         
            ];

            for (let i = 0; i < 6; i++) {
                vcAndDiscloseProof.pubSignals[CIRCUIT_CONSTANTS.VC_AND_DISCLOSE_CURRENT_DATE_INDEX + i] = dateComponents[i].toString();
            }

            await expect(
                hub.verifyVcAndDiscloseAndGetResult(vcAndDiscloseProof)
            ).to.be.revertedWithCustomError(hub, "CURRENT_DATE_NOT_IN_VALID_RANGE");
        });

        it("should fail with invalid OFAC root", async () => {
            const {hub, registry, owner, user1, mockPassport} = deployedActors;

            const registerSecret = "1234567890";
            const dscSecret = generateDscSecret();

            // Register the commitment first
            const registerProof = await generateRegisterProof(
                registerSecret, 
                dscSecret, 
                mockPassport
            );
            const dscProof = await generateDscProof(
                dscSecret, 
                mockPassport.dsc, 
                1664
            );

            const passportProof: PassportProof = {
                registerCircuitVerifierId: RegisterVerifierId.register_sha256_sha256_sha256_rsa_65537_4096,
                dscCircuitVerifierId: DscVerifierId.dsc_rsa_sha256_65537_4096,
                registerCircuitProof: registerProof,
                dscCircuitProof: dscProof
            };

            await hub.verifyAndRegisterPassportCommitment(passportProof);

            await registry.updateOfacRoot("123456789");

            // Generate proof without registering commitment
            const imt = new LeanIMT<bigint>((a: bigint, b: bigint) => poseidon2([a, b]));
            const commitment = generateCommitment(registerSecret, ATTESTATION_ID.E_PASSPORT, mockPassport);
            await imt.insert(BigInt(commitment));
            
            const vcAndDiscloseProof = await generateVcAndDiscloseProof(
                registerSecret,
                BigInt(ATTESTATION_ID.E_PASSPORT).toString(),
                mockPassport,
                "test-scope",
                new Array(88).fill("1"),
                "1",
                imt,
                "20",
            );

            await expect(
                hub.verifyVcAndDiscloseAndGetResult(vcAndDiscloseProof)
            ).to.be.revertedWithCustomError(hub, "INVALID_OFAC_ROOT");
        });

        it("should fail with invalid VC and Disclose proof", async () => {
            const {hub, registry, owner, user1, mockPassport} = deployedActors;

            const registerSecret = "1234567890";
            const dscSecret = generateDscSecret();

            // Register the commitment first
            const registerProof = await generateRegisterProof(
                registerSecret, 
                dscSecret, 
                mockPassport
            );
            const dscProof = await generateDscProof(
                dscSecret, 
                mockPassport.dsc, 
                1664
            );

            const passportProof: PassportProof = {
                registerCircuitVerifierId: RegisterVerifierId.register_sha256_sha256_sha256_rsa_65537_4096,
                dscCircuitVerifierId: DscVerifierId.dsc_rsa_sha256_65537_4096,
                registerCircuitProof: registerProof,
                dscCircuitProof: dscProof
            };

            await hub.verifyAndRegisterPassportCommitment(passportProof);

            // Generate proof without registering commitment
            const imt = new LeanIMT<bigint>((a: bigint, b: bigint) => poseidon2([a, b]));
            const commitment = generateCommitment(registerSecret, ATTESTATION_ID.E_PASSPORT, mockPassport);
            await imt.insert(BigInt(commitment));
            
            const vcAndDiscloseProof = await generateVcAndDiscloseProof(
                registerSecret,
                BigInt(ATTESTATION_ID.E_PASSPORT).toString(),
                mockPassport,
                "test-scope",
                new Array(88).fill("1"),
                "1",
                imt,
                "20",
            );
            vcAndDiscloseProof.a[0] = "0";

            await expect(
                hub.verifyVcAndDiscloseAndGetResult(vcAndDiscloseProof)
            ).to.be.revertedWithCustomError(hub, "INVALID_VC_AND_DISCLOSE_PROOF");
        });
    });
}); 