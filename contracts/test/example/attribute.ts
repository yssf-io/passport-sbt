import { expect } from "chai";
import { deploySystemFixtures } from "../utils/deployment";
import { DeployedActors } from "../utils/types";
import { ethers } from "hardhat";
import { generateDscSecret } from "../../../common/src/utils/csca";
import { RegisterVerifierId, DscVerifierId } from "../../../common/src/constants/constants";
import { PassportProof } from "../utils/types";
import { ATTESTATION_ID } from "../utils/constants";
import { generateRegisterProof, generateDscProof, generateVcAndDiscloseProof } from "../utils/generateProof";
import { LeanIMT } from "@openpassport/zk-kit-lean-imt";
import { poseidon2 } from "poseidon-lite";
import { generateCommitment } from "../../../common/src/utils/passports/passport";
import { generateRandomFieldElement } from "../utils/utils";
import { PassportData } from "../../../common/src/utils/types";
import { genMockPassportData } from "../../../common/src/utils/passports/genMockPassportData";
import { initPassportDataParsing } from "../../../common/src/utils/passports/passport";
import { CIRCUIT_CONSTANTS } from "../utils/constants";
import { BigNumberish } from "ethers";

describe("Attribute Tests", () => {
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

    describe("Get Readable Dg1 Attributes", () => {
        it("should return correct passport attributes", async () => {
            const attributeContractFactory = await ethers.getContractFactory("Attribute");
            const attributeContract = await attributeContractFactory.deploy();
            await attributeContract.waitForDeployment();

            const registerSecret = generateRandomFieldElement();
            let mockPassport = genMockPassportData(
                "sha256",
                "sha256",
                "rsa_sha256_65537_2048",
                "FRA",
                "940131",
                "401031"
            );
            mockPassport = initPassportDataParsing(mockPassport);

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

            const revealedData_packed: [BigNumberish, BigNumberish, BigNumberish] = [
                vcAndDiscloseProof.pubSignals[CIRCUIT_CONSTANTS.VC_AND_DISCLOSE_REVEALED_DATA_PACKED_INDEX],
                vcAndDiscloseProof.pubSignals[CIRCUIT_CONSTANTS.VC_AND_DISCLOSE_REVEALED_DATA_PACKED_INDEX + 1],
                vcAndDiscloseProof.pubSignals[CIRCUIT_CONSTANTS.VC_AND_DISCLOSE_REVEALED_DATA_PACKED_INDEX + 2]
            ];
            const attributeTypes = [0, 1, 2, 3, 4, 5, 6, 7, 8];

            const readableAttrs = await attributeContract.getReadableDg1Attributes(
                revealedData_packed,
                attributeTypes
            );

            expect(readableAttrs[0]).to.equal("FRA");
            expect(readableAttrs[1]).to.equal("DUPONT<<ALPHONSE<HUGHUES<ALBERT<<<<<<<<");
            expect(readableAttrs[2]).to.equal("15AA81234");
            expect(readableAttrs[3]).to.equal("FRA");
            expect(readableAttrs[4]).to.equal("940131");
            expect(readableAttrs[5]).to.equal("M");
            expect(readableAttrs[6]).to.equal("401031");
            expect(readableAttrs[7]).to.equal("20");
            expect(readableAttrs[8]).to.equal("1");
        });
    });
});
