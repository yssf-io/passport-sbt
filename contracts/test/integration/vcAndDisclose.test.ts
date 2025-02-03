import { expect } from "chai";
import { deploySystemFixtures } from "../utils/deployment";
import { DeployedActors } from "../utils/types";
import { ethers } from "hardhat";
import { CIRCUIT_CONSTANTS } from "../utils/constants";
import { ATTESTATION_ID } from "../utils/constants";
import { generateVcAndDiscloseProof } from "../utils/generateProof";
import { LeanIMT } from "@openpassport/zk-kit-lean-imt";
import { poseidon2 } from "poseidon-lite";
import { generateCommitment } from "../../../common/src/utils/passports/passport";
import { BigNumberish } from "ethers";
import { generateRandomFieldElement } from "../utils/utils";
import { SMT, ChildNodes } from "@openpassport/zk-kit-smt";
import { getStartOfDayTimestamp } from "../utils/utils";
import { Formatter, CircuitAttributeHandler } from "../utils/formatter";

describe("VC and Disclose", () => {
    let deployedActors: DeployedActors;
    let snapshotId: string;
    let baseVcAndDiscloseProof: any;
    let vcAndDiscloseProof: any;
    let registerSecret: any;
    let imt: any;
    let commitment: any;
    let nullifier: any;

    before(async () => {
        deployedActors = await deploySystemFixtures();
        registerSecret = generateRandomFieldElement();
        nullifier = generateRandomFieldElement();
        commitment = generateCommitment(registerSecret, ATTESTATION_ID.E_PASSPORT, deployedActors.mockPassport);
        const hashFunction = (a: bigint, b: bigint) => poseidon2([a, b]);
        imt = new LeanIMT<bigint>(hashFunction);
        await imt.insert(BigInt(commitment));

        baseVcAndDiscloseProof = await generateVcAndDiscloseProof(
            registerSecret,
            BigInt(ATTESTATION_ID.E_PASSPORT).toString(),
            deployedActors.mockPassport,
            "test-scope",
            new Array(88).fill("1"),
            "1",
            imt,
            "20",
        );
        snapshotId = await ethers.provider.send("evm_snapshot", []);
    });

    beforeEach(async () => {
        vcAndDiscloseProof = structuredClone(baseVcAndDiscloseProof);
    });

    afterEach(async () => {
        await ethers.provider.send("evm_revert", [snapshotId]);
        snapshotId = await ethers.provider.send("evm_snapshot", []);
    });

    describe("Verify VC and Disclose", () => {

        it("should verify and get result successfully", async () => {
            const {hub, registry, owner} = deployedActors;

            await registry.connect(owner).devAddIdentityCommitment(
                ATTESTATION_ID.E_PASSPORT,
                nullifier,
                commitment
            );

            const forbiddenCountriesListPacked = vcAndDiscloseProof.pubSignals[CIRCUIT_CONSTANTS.VC_AND_DISCLOSE_FORBIDDEN_COUNTRIES_LIST_PACKED_INDEX];

            const vcAndDiscloseHubProof = {
                olderThanEnabled: true,
                olderThan: "20",
                forbiddenCountriesEnabled: true,
                forbiddenCountriesListPacked: forbiddenCountriesListPacked,
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
            expect(result.forbiddenCountriesListPacked).to.equal(4276545n);
        });

        it("should not call verifyVcAndDisclose with non-proxy address", async() => {
            const {hubImpl, registry, owner} = deployedActors;

            await registry.connect(owner).devAddIdentityCommitment(
                ATTESTATION_ID.E_PASSPORT,
                nullifier,
                commitment
            );

            const forbiddenCountriesListPacked = vcAndDiscloseProof.pubSignals[CIRCUIT_CONSTANTS.VC_AND_DISCLOSE_FORBIDDEN_COUNTRIES_LIST_PACKED_INDEX];

            const vcAndDiscloseHubProof = {
                olderThanEnabled: false,
                olderThan: "20",
                forbiddenCountriesEnabled: false,
                forbiddenCountriesListPacked: forbiddenCountriesListPacked,
                ofacEnabled: false,
                vcAndDiscloseProof: vcAndDiscloseProof
            }

            await expect(hubImpl.verifyVcAndDisclose(vcAndDiscloseHubProof))
                .to.be.revertedWithCustomError(hubImpl, "UUPSUnauthorizedCallContext");
        });

        it("should fail with invalid identity commitment root", async () => {
            const {hub, registry, owner} = deployedActors;

            await registry.connect(owner).devAddIdentityCommitment(
                ATTESTATION_ID.E_PASSPORT,
                nullifier,
                commitment
            );
            const forbiddenCountriesListPacked = vcAndDiscloseProof.pubSignals[CIRCUIT_CONSTANTS.VC_AND_DISCLOSE_FORBIDDEN_COUNTRIES_LIST_PACKED_INDEX];
            vcAndDiscloseProof.pubSignals[CIRCUIT_CONSTANTS.VC_AND_DISCLOSE_MERKLE_ROOT_INDEX] = generateRandomFieldElement();
            const vcAndDiscloseHubProof = {
                olderThanEnabled: true,
                olderThan: "20",
                forbiddenCountriesEnabled: true,
                forbiddenCountriesListPacked: forbiddenCountriesListPacked,
                ofacEnabled: true,
                vcAndDiscloseProof: vcAndDiscloseProof
            }

            await expect(
                hub.verifyVcAndDisclose(vcAndDiscloseHubProof)
            ).to.be.revertedWithCustomError(hub, "INVALID_COMMITMENT_ROOT");
        });

        it("should fail with invalid OFAC root", async () => {
            const {hub, registry, owner} = deployedActors;

            await registry.connect(owner).devAddIdentityCommitment(
                ATTESTATION_ID.E_PASSPORT,
                nullifier,
                commitment
            );
            const forbiddenCountriesListPacked = vcAndDiscloseProof.pubSignals[CIRCUIT_CONSTANTS.VC_AND_DISCLOSE_FORBIDDEN_COUNTRIES_LIST_PACKED_INDEX];
            vcAndDiscloseProof.pubSignals[CIRCUIT_CONSTANTS.VC_AND_DISCLOSE_SMT_ROOT_INDEX] = generateRandomFieldElement();

            const vcAndDiscloseHubProof = {
                olderThanEnabled: true,
                olderThan: "20",
                forbiddenCountriesEnabled: true,
                forbiddenCountriesListPacked: forbiddenCountriesListPacked,
                ofacEnabled: true,
                vcAndDiscloseProof: vcAndDiscloseProof
            }

            await expect(
                hub.verifyVcAndDisclose(vcAndDiscloseHubProof)
            ).to.be.revertedWithCustomError(hub, "INVALID_OFAC_ROOT");
        });

        it("should fail with invalid current date (more than + 1 day)", async () => {
            const {hub, registry, owner} = deployedActors;

            await registry.connect(owner).devAddIdentityCommitment(
                ATTESTATION_ID.E_PASSPORT,
                nullifier,
                commitment
            );
            const currentBlock = await ethers.provider.getBlock('latest');
            const oneDayAfter = getStartOfDayTimestamp(currentBlock!.timestamp) + 24 * 60 * 60;
            
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

            const forbiddenCountriesListPacked = vcAndDiscloseProof.pubSignals[CIRCUIT_CONSTANTS.VC_AND_DISCLOSE_FORBIDDEN_COUNTRIES_LIST_PACKED_INDEX];
            const vcAndDiscloseHubProof = {
                olderThanEnabled: true,
                olderThan: "20",
                forbiddenCountriesEnabled: true,
                forbiddenCountriesListPacked: forbiddenCountriesListPacked,
                ofacEnabled: true,
                vcAndDiscloseProof: vcAndDiscloseProof
            };

            await expect(
                hub.verifyVcAndDisclose(vcAndDiscloseHubProof)
            ).to.be.revertedWithCustomError(hub, "CURRENT_DATE_NOT_IN_VALID_RANGE");
        });

        it("should not revert when current date is within + 1 day", async () => {
            const {hub, registry, owner} = deployedActors;

            await registry.connect(owner).devAddIdentityCommitment(
                ATTESTATION_ID.E_PASSPORT,
                nullifier,
                commitment
            );
            const currentBlock = await ethers.provider.getBlock('latest');

            const oneDayAfter = getStartOfDayTimestamp(currentBlock!.timestamp) + 24 * 60 * 60 - 1;
            
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

            const forbiddenCountriesListPacked = vcAndDiscloseProof.pubSignals[CIRCUIT_CONSTANTS.VC_AND_DISCLOSE_FORBIDDEN_COUNTRIES_LIST_PACKED_INDEX];
            const vcAndDiscloseHubProof = {
                olderThanEnabled: true,
                olderThan: "20",
                forbiddenCountriesEnabled: true,
                forbiddenCountriesListPacked: forbiddenCountriesListPacked,
                ofacEnabled: true,
                vcAndDiscloseProof: vcAndDiscloseProof
            };

            await expect (
                hub.verifyVcAndDisclose(vcAndDiscloseHubProof)
            ).to.not.be.reverted;
        });

        it("should fail with invalid current date (- 1 day)", async () => {
            
            const {hub, registry, owner} = deployedActors;

            await registry.connect(owner).devAddIdentityCommitment(
                ATTESTATION_ID.E_PASSPORT,
                nullifier,
                commitment
                );

            const forbiddenCountriesListPacked = vcAndDiscloseProof.pubSignals[CIRCUIT_CONSTANTS.VC_AND_DISCLOSE_FORBIDDEN_COUNTRIES_LIST_PACKED_INDEX];

            const vcAndDiscloseHubProof = {
                olderThanEnabled: true,
                olderThan: "20",
                forbiddenCountriesEnabled: true,
                forbiddenCountriesListPacked: forbiddenCountriesListPacked,
                ofacEnabled: true,
                vcAndDiscloseProof: vcAndDiscloseProof
            }

            const currentBlock = await ethers.provider.getBlock('latest');
            const oneDayBefore = getStartOfDayTimestamp(currentBlock!.timestamp) - 1;
            
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
                hub.verifyVcAndDisclose(vcAndDiscloseHubProof)
            ).to.be.revertedWithCustomError(hub, "CURRENT_DATE_NOT_IN_VALID_RANGE");
        });

        it("should not revert when current date is slightly less than - 1 day", async () => {
            const {hub, registry, owner} = deployedActors;

            await registry.connect(owner).devAddIdentityCommitment(
                ATTESTATION_ID.E_PASSPORT,
                nullifier,
                commitment
            );
            const currentBlock = await ethers.provider.getBlock('latest');

            const oneDayBefore = getStartOfDayTimestamp(currentBlock!.timestamp);
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

            const forbiddenCountriesListPacked = vcAndDiscloseProof.pubSignals[CIRCUIT_CONSTANTS.VC_AND_DISCLOSE_FORBIDDEN_COUNTRIES_LIST_PACKED_INDEX];
            const vcAndDiscloseHubProof = {
                olderThanEnabled: true,
                olderThan: "20",
                forbiddenCountriesEnabled: true,
                forbiddenCountriesListPacked: forbiddenCountriesListPacked,
                ofacEnabled: true,
                vcAndDiscloseProof: vcAndDiscloseProof
            };

            await expect(
                hub.verifyVcAndDisclose(vcAndDiscloseHubProof)
            ).to.not.be.reverted;
        });

        it("should succeed with bigger value than older than", async () => {
            const {hub, registry, owner} = deployedActors;

            await registry.connect(owner).devAddIdentityCommitment(
                ATTESTATION_ID.E_PASSPORT,
                nullifier,
                commitment
                );
            const forbiddenCountriesListPacked = vcAndDiscloseProof.pubSignals[CIRCUIT_CONSTANTS.VC_AND_DISCLOSE_FORBIDDEN_COUNTRIES_LIST_PACKED_INDEX];

            const vcAndDiscloseHubProof = {
                olderThanEnabled: true,
                olderThan: "18",
                forbiddenCountriesEnabled: true,
                forbiddenCountriesListPacked: forbiddenCountriesListPacked,
                ofacEnabled: true,
                vcAndDiscloseProof: vcAndDiscloseProof
            }

            await expect(
                hub.verifyVcAndDisclose(vcAndDiscloseHubProof)
            ).to.be.not.reverted;
        });

        it("should fail with invalid older than", async () => {
            const {hub, registry, owner} = deployedActors;

            await registry.connect(owner).devAddIdentityCommitment(
                ATTESTATION_ID.E_PASSPORT,
                nullifier,
                commitment
            );

            const forbiddenCountriesListPacked = vcAndDiscloseProof.pubSignals[CIRCUIT_CONSTANTS.VC_AND_DISCLOSE_FORBIDDEN_COUNTRIES_LIST_PACKED_INDEX];

            const vcAndDiscloseHubProof = {
                olderThanEnabled: true,
                olderThan: "21",
                forbiddenCountriesEnabled: false,
                forbiddenCountriesListPacked: forbiddenCountriesListPacked,
                ofacEnabled: false,
                vcAndDiscloseProof: vcAndDiscloseProof
            }

            await expect(
                hub.verifyVcAndDisclose(vcAndDiscloseHubProof)
            ).to.be.revertedWithCustomError(hub, "INVALID_OLDER_THAN");
        });

        it("should fail with if listed in OFAC", async () => {
            const {hub, registry, owner, mockPassport} = deployedActors;

            await registry.connect(owner).devAddIdentityCommitment(
                ATTESTATION_ID.E_PASSPORT,
                nullifier,
                commitment
                );

            const hashFunction = (a: bigint, b: bigint) => poseidon2([a, b]);
            const imt = new LeanIMT<bigint>(hashFunction);
            await imt.insert(BigInt(commitment));
    
            const hash2 = (childNodes: ChildNodes) => poseidon2(childNodes);
            const smt = new SMT(hash2, true);

            const vcAndDiscloseProof = await generateVcAndDiscloseProof(
                registerSecret,
                BigInt(ATTESTATION_ID.E_PASSPORT).toString(),
                mockPassport,
                "test-scope",
                new Array(88).fill("1"),
                "1",
                imt,
                "20",
                smt,
                "0",
            );
            const forbiddenCountriesListPacked = vcAndDiscloseProof.pubSignals[CIRCUIT_CONSTANTS.VC_AND_DISCLOSE_FORBIDDEN_COUNTRIES_LIST_PACKED_INDEX];

            const vcAndDiscloseHubProof = {
                olderThanEnabled: true,
                olderThan: "20",
                forbiddenCountriesEnabled: false,
                forbiddenCountriesListPacked: forbiddenCountriesListPacked,
                ofacEnabled: true,
                vcAndDiscloseProof: vcAndDiscloseProof
            }

            await expect(
                hub.verifyVcAndDisclose(vcAndDiscloseHubProof)
            ).to.be.revertedWithCustomError(hub, "INVALID_OFAC");
        });

        it("should fail with invalid forbidden countries", async () => {
            const {hub, registry, owner} = deployedActors;

            await registry.connect(owner).devAddIdentityCommitment(
                ATTESTATION_ID.E_PASSPORT,
                nullifier,
                commitment
                );
            const forbiddenCountriesListPacked = generateRandomFieldElement();

            const vcAndDiscloseHubProof = {
                olderThanEnabled: true,
                olderThan: "20",
                forbiddenCountriesEnabled: true,
                forbiddenCountriesListPacked: forbiddenCountriesListPacked,
                ofacEnabled: true,
                vcAndDiscloseProof: vcAndDiscloseProof
            }

            await expect(
                hub.verifyVcAndDisclose(vcAndDiscloseHubProof)
            ).to.be.revertedWithCustomError(hub, "INVALID_FORBIDDEN_COUNTRIES");
        });

        it("should fail with invalid VC and Disclose proof", async () => {
            const {hub, registry, owner} = deployedActors;

            await registry.connect(owner).devAddIdentityCommitment(
                ATTESTATION_ID.E_PASSPORT,
                nullifier,
                commitment
            );

            const forbiddenCountriesListPacked = vcAndDiscloseProof.pubSignals[CIRCUIT_CONSTANTS.VC_AND_DISCLOSE_FORBIDDEN_COUNTRIES_LIST_PACKED_INDEX];
            vcAndDiscloseProof.a[0] = generateRandomFieldElement();

            const vcAndDiscloseHubProof = {
                olderThanEnabled: false,
                olderThan: "20",
                forbiddenCountriesEnabled: false,
                forbiddenCountriesListPacked: forbiddenCountriesListPacked,
                ofacEnabled: false,
                vcAndDiscloseProof: vcAndDiscloseProof
            }

            await expect(
                hub.verifyVcAndDisclose(vcAndDiscloseHubProof)
            ).to.be.revertedWithCustomError(hub, "INVALID_VC_AND_DISCLOSE_PROOF");
        });
    });

    describe("readable parsers", () =>{
        async function setupVcAndDiscloseTest(types: string[]) {
            const {hub} = deployedActors;
            

            let revealedDataPacked = [BigInt(0), BigInt(0), BigInt(0)];
            for (let i = 0; i < 3; i++) {
                revealedDataPacked[i] = BigInt(vcAndDiscloseProof.pubSignals[CIRCUIT_CONSTANTS.VC_AND_DISCLOSE_REVEALED_DATA_PACKED_INDEX + i]);
            };
            const bytes = Formatter.fieldElementsToBytes(revealedDataPacked as [bigint, bigint, bigint]);
            const readableData = await hub.getReadableRevealedData(
                revealedDataPacked as [BigNumberish, BigNumberish, BigNumberish],
                types
            );


            return { readableData, bytes };
        }

        it("should fail when getReadableRevealedData is called by non-proxy", async() => {
            const {hubImpl} = deployedActors;
            let revealedDataPacked = [BigInt(0), BigInt(0), BigInt(0)];
            for (let i = 0; i < 3; i++) {
                revealedDataPacked[i] = BigInt(vcAndDiscloseProof.pubSignals[CIRCUIT_CONSTANTS.VC_AND_DISCLOSE_REVEALED_DATA_PACKED_INDEX + i]);
            };
            await expect(
                hubImpl.getReadableRevealedData(
                    revealedDataPacked as [BigNumberish, BigNumberish, BigNumberish],
                    ['0']
                )
            ).to.be.revertedWithCustomError(hubImpl, "UUPSUnauthorizedCallContext");
        });

        it("formatter and CircuitAttributeHandler are working fine", async () => {
            const { readableData, bytes } = await setupVcAndDiscloseTest(['0', '1', '2', '3', '4', '5', '6', '7', '8']);
            
            expect(CircuitAttributeHandler.getIssuingState(bytes)).to.equal(readableData[0]);
            expect(CircuitAttributeHandler.getName(bytes)).to.deep.equal(readableData[1]);
            expect(CircuitAttributeHandler.getPassportNumber(bytes)).to.equal(readableData[2]);
            expect(CircuitAttributeHandler.getNationality(bytes)).to.equal(readableData[3]);
            expect(CircuitAttributeHandler.getDateOfBirth(bytes)).to.equal(readableData[4]);
            expect(CircuitAttributeHandler.getGender(bytes)).to.equal(readableData[5]);
            expect(CircuitAttributeHandler.getExpiryDate(bytes)).to.equal(readableData[6]);
            expect(CircuitAttributeHandler.getOlderThan(bytes)).to.equal(readableData[7]);
            expect(CircuitAttributeHandler.getOfac(bytes)).to.equal(readableData[8]);
        });

        it("should return all data", async () => {
            const { readableData } = await setupVcAndDiscloseTest(['0', '1', '2', '3', '4', '5', '6', '7', '8']);
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

        it("should only return issuing state", async() => {
            const { readableData } = await setupVcAndDiscloseTest(['0']);
            expect(readableData[0]).to.equal('FRA');
            expect(readableData[1]).to.deep.equal([]);
            expect(readableData[2]).to.equal('');
            expect(readableData[3]).to.equal('');
            expect(readableData[4]).to.equal('');
            expect(readableData[5]).to.equal('');
            expect(readableData[6]).to.equal('');
            expect(readableData[7]).to.equal(0n);
            expect(readableData[8]).to.equal(0n)
        });

        it("should only return name", async () => {
            const { readableData } = await setupVcAndDiscloseTest(['1']);
            expect(readableData[0]).to.equal('');
            expect(readableData[1]).to.deep.equal([ 'ALPHONSE HUGHUES ALBERT', 'DUPONT' ]);
            expect(readableData[2]).to.equal('');
            expect(readableData[3]).to.equal('');
            expect(readableData[4]).to.equal('');
            expect(readableData[5]).to.equal('');
            expect(readableData[6]).to.equal('');
            expect(readableData[7]).to.equal(0n);
            expect(readableData[8]).to.equal(0n);
        });

        it("should only return passport number", async () => {
            const { readableData } = await setupVcAndDiscloseTest(['2']);
            expect(readableData[0]).to.equal('');
            expect(readableData[1]).to.deep.equal([]);
            expect(readableData[2]).to.equal('15AA81234');
            expect(readableData[3]).to.equal('');
            expect(readableData[4]).to.equal('');
            expect(readableData[5]).to.equal('');
            expect(readableData[6]).to.equal('');
            expect(readableData[7]).to.equal(0n);
            expect(readableData[8]).to.equal(0n);   
        });

        it("should only return nationality", async () => {
            const { readableData } = await setupVcAndDiscloseTest(['3']);
            expect(readableData[0]).to.equal('');
            expect(readableData[1]).to.deep.equal([]);
            expect(readableData[2]).to.equal('');
            expect(readableData[3]).to.equal('FRA');
            expect(readableData[4]).to.equal('');
            expect(readableData[5]).to.equal('');
            expect(readableData[6]).to.equal('');
            expect(readableData[7]).to.equal(0n);
            expect(readableData[8]).to.equal(0n);   
        });

        it("should only return data of birth", async () => {
            const { readableData } = await setupVcAndDiscloseTest(['4']);
            expect(readableData[0]).to.equal('');
            expect(readableData[1]).to.deep.equal([]);
            expect(readableData[2]).to.equal('');
            expect(readableData[3]).to.equal('');
            expect(readableData[4]).to.equal('31-01-94');
            expect(readableData[5]).to.equal('');
            expect(readableData[6]).to.equal('');
            expect(readableData[7]).to.equal(0n);
            expect(readableData[8]).to.equal(0n);   
        });

        it("should only return gender", async () => {
            const { readableData } = await setupVcAndDiscloseTest(['5']);
            expect(readableData[0]).to.equal('');
            expect(readableData[1]).to.deep.equal([]);
            expect(readableData[2]).to.equal('');
            expect(readableData[3]).to.equal('');
            expect(readableData[4]).to.equal('');
            expect(readableData[5]).to.equal('M');
            expect(readableData[6]).to.equal('');
            expect(readableData[7]).to.equal(0n);
            expect(readableData[8]).to.equal(0n);   
        });

        it("should only return expiry date", async () => {
            const { readableData } = await setupVcAndDiscloseTest(['6']);
            expect(readableData[0]).to.equal('');
            expect(readableData[1]).to.deep.equal([]);
            expect(readableData[2]).to.equal('');
            expect(readableData[3]).to.equal('');
            expect(readableData[4]).to.equal('');
            expect(readableData[5]).to.equal('');
            expect(readableData[6]).to.equal('31-10-40');
            expect(readableData[7]).to.equal(0n);
            expect(readableData[8]).to.equal(0n);   
        });

        it("should only return older than", async () => {
            const { readableData } = await setupVcAndDiscloseTest(['7']);
            expect(readableData[0]).to.equal('');
            expect(readableData[1]).to.deep.equal([]);
            expect(readableData[2]).to.equal('');
            expect(readableData[3]).to.equal('');
            expect(readableData[4]).to.equal('');
            expect(readableData[5]).to.equal('');
            expect(readableData[6]).to.equal('');
            expect(readableData[7]).to.equal(20n);
            expect(readableData[8]).to.equal(0n);   
        });
   
        it("should only return ofac", async () => {
            const { readableData } = await setupVcAndDiscloseTest(['8']);
            expect(readableData[0]).to.equal('');
            expect(readableData[1]).to.deep.equal([]);
            expect(readableData[2]).to.equal('');
            expect(readableData[3]).to.equal('');
            expect(readableData[4]).to.equal('');
            expect(readableData[5]).to.equal('');
            expect(readableData[6]).to.equal('');
            expect(readableData[7]).to.equal(0n);
            expect(readableData[8]).to.equal(1n);
        });

        it("should return nothing", async () => {
            const { readableData } = await setupVcAndDiscloseTest([]);
            expect(readableData[0]).to.equal('');
            expect(readableData[1]).to.deep.equal([]);
            expect(readableData[2]).to.equal('');
            expect(readableData[3]).to.equal('');
            expect(readableData[4]).to.equal('');
            expect(readableData[5]).to.equal('');
            expect(readableData[6]).to.equal('');
            expect(readableData[7]).to.equal(0n);
            expect(readableData[8]).to.equal(0n);
        });

        it("should parse forbidden countries with CircuitAttributeHandler", async () => {
            const { hub } = deployedActors;

            const forbiddenCountriesListPacked = vcAndDiscloseProof.pubSignals[CIRCUIT_CONSTANTS.VC_AND_DISCLOSE_FORBIDDEN_COUNTRIES_LIST_PACKED_INDEX];
            const readableForbiddenCountries = await hub.getReadableForbiddenCountries(forbiddenCountriesListPacked);
            
            expect(readableForbiddenCountries[0]).to.equal(Formatter.extractForbiddenCountriesFromPacked(BigInt(vcAndDiscloseProof.pubSignals[CIRCUIT_CONSTANTS.VC_AND_DISCLOSE_FORBIDDEN_COUNTRIES_LIST_PACKED_INDEX]))[0]);
            expect(readableForbiddenCountries[0]).to.equal('AAA');
        });

        
    });
}); 