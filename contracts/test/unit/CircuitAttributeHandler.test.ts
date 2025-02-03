import { expect } from "chai";
import { ethers } from "hardhat";
import { TestCircuitAttributeHandler } from "../../typechain-types";
import { CircuitAttributeHandler } from "../utils/formatter";

describe("CircuitAttributeHandler", function () {
    let testHandler: TestCircuitAttributeHandler;

    before(async function () {
        const TestHandlerFactory = await ethers.getContractFactory("TestCircuitAttributeHandler");
        testHandler = await TestHandlerFactory.deploy();
        await testHandler.waitForDeployment();
    });

    const mrz = ethers.toUtf8Bytes(
        "P<UTOERIKSSON<<ANNA<MARIA<<<<<<<<<<<<<<<<<<<" +
        "L898902C36UTO7408122F1204159ZE184226B<<<<<1018"
    );
    const sampleMRZ = new Uint8Array([...mrz, 1]);

    describe("getIssuingState", function () {
        it("should match contract and ts implementation", async function () {
            const contractResult = await testHandler.testGetIssuingState(sampleMRZ);
            const tsResult = CircuitAttributeHandler.getIssuingState(sampleMRZ);
            expect(contractResult).to.equal(tsResult);
            expect(contractResult).to.equal("UTO");
        });
    });

    describe("getName", function () {
        it("should match contract and ts implementation", async function () {
            const contractResult = await testHandler.testGetName(sampleMRZ);
            const tsResult = CircuitAttributeHandler.getName(sampleMRZ);
            expect(contractResult[0]).to.equal(tsResult[0]);
            expect(contractResult[1]).to.equal(tsResult[1]);
            expect(contractResult[0]).to.equal("ANNA MARIA");
            expect(contractResult[1]).to.equal("ERIKSSON");
        });
    });

    describe("getPassportNumber", function () {
        it("should match contract and ts implementation", async function () {
            const contractResult = await testHandler.testGetPassportNumber(sampleMRZ);
            const tsResult = CircuitAttributeHandler.getPassportNumber(sampleMRZ);
            expect(contractResult).to.equal(tsResult);
            expect(contractResult).to.equal("L898902C3");
        });
    });

    describe("getNationality", function () {
        it("should match contract and ts implementation", async function () {
            const contractResult = await testHandler.testGetNationality(sampleMRZ);
            const tsResult = CircuitAttributeHandler.getNationality(sampleMRZ);
            expect(contractResult).to.equal(tsResult);
            expect(contractResult).to.equal("UTO");
        });
    });

    describe("getDateOfBirth", function () {
        it("should match contract and ts implementation", async function () {
            const contractResult = await testHandler.testGetDateOfBirth(sampleMRZ);
            const tsResult = CircuitAttributeHandler.getDateOfBirth(sampleMRZ);
            expect(contractResult).to.equal(tsResult);
            expect(contractResult).to.equal("12-08-74");
        });
    });

    describe("getGender", function () {
        it("should match contract and ts implementation", async function () {
            const contractResult = await testHandler.testGetGender(sampleMRZ);
            const tsResult = CircuitAttributeHandler.getGender(sampleMRZ);
            expect(contractResult).to.equal(tsResult);
            expect(contractResult).to.equal("F");
        });
    });

    describe("getExpiryDate", function () {
        it("should match contract and ts implementation", async function () {
            const contractResult = await testHandler.testGetExpiryDate(sampleMRZ);
            const tsResult = CircuitAttributeHandler.getExpiryDate(sampleMRZ);
            expect(contractResult).to.equal(tsResult);
            expect(contractResult).to.equal("15-04-12");
        });
    });

    describe("getOlderThan and compareOlderThan", function () {
        it("should match contract and ts implementation for getOlderThan", async function () {
            const contractResult = await testHandler.testGetOlderThan(sampleMRZ);
            const tsResult = CircuitAttributeHandler.getOlderThan(sampleMRZ);
            expect(contractResult).to.equal(tsResult);
            expect(contractResult).to.equal(18);
        });

        it("should match contract and ts implementation for compareOlderThan", async function () {
            const contractResult = await testHandler.testCompareOlderThan(sampleMRZ, 18);
            const tsResult = CircuitAttributeHandler.compareOlderThan(sampleMRZ, 18);
            expect(contractResult).to.equal(tsResult);
            expect(contractResult).to.be.true;

            const contractResultFalse = await testHandler.testCompareOlderThan(sampleMRZ, 19);
            const tsResultFalse = CircuitAttributeHandler.compareOlderThan(sampleMRZ, 19);
            expect(contractResultFalse).to.equal(tsResultFalse);
            expect(contractResultFalse).to.be.false;
        });
    });

    describe("getOfac and compareOfac", function () {
        it("should match contract and ts implementation for getOfac", async function () {
            const contractResult = await testHandler.testGetOfac(sampleMRZ);
            const tsResult = CircuitAttributeHandler.getOfac(sampleMRZ);
            expect(contractResult).to.equal(tsResult);
            expect(contractResult).to.equal(1);
        });

        it("should match contract and ts implementation for compareOfac", async function () {
            const contractResult = await testHandler.testCompareOfac(sampleMRZ);
            const tsResult = CircuitAttributeHandler.compareOfac(sampleMRZ);
            expect(contractResult).to.equal(tsResult);
            expect(contractResult).to.be.true;

            const mrz2 = ethers.toUtf8Bytes(
                "P<UTOERIKSSON<<ANNA<MARIA<<<<<<<<<<<<<<<<<<<" +
                "L898902C36UTO7408122F1204159ZE184226B<<<<<10180"
            );
            const sampleMRZ2 = new Uint8Array([...mrz2, 0]);

            const contractResultFalse = await testHandler.testCompareOfac(sampleMRZ2);
            const tsResultFalse = CircuitAttributeHandler.compareOfac(sampleMRZ2);
            expect(contractResultFalse).to.equal(tsResultFalse);
            expect(contractResultFalse).to.be.false;
        });
    });

    describe("extractStringAttribute", function () {
        it("should match contract and ts implementation for different positions", async function () {
            const testCases = [
                { start: 2, end: 4, expected: "UTO" },
                { start: 44, end: 52, expected: "L898902C3" },
                { start: 54, end: 56, expected: "UTO" },
                { start: 64, end: 64, expected: "F" }
            ];

            for (const testCase of testCases) {
                const contractResult = await testHandler.testExtractStringAttribute(
                    sampleMRZ,
                    testCase.start,
                    testCase.end
                );
                const tsResult = CircuitAttributeHandler.extractStringAttribute(
                    sampleMRZ,
                    testCase.start,
                    testCase.end
                );
                expect(contractResult).to.equal(tsResult);
                expect(contractResult).to.equal(testCase.expected);
            }
        });

        it("should handle errors consistently between contract and ts", async function () {
            const shortMRZ = ethers.toUtf8Bytes("ABC");
            await expect(testHandler.testExtractStringAttribute(shortMRZ, 0, 5))
                .to.be.revertedWithCustomError(testHandler, "INSUFFICIENT_CHARCODE_LEN");
            
            expect(() => CircuitAttributeHandler.extractStringAttribute(shortMRZ, 0, 5))
                .to.throw("INSUFFICIENT_CHARCODE_LEN");
        });

        it("should match contract and ts implementation for empty range", async function () {
            const contractResult = await testHandler.testExtractStringAttribute(sampleMRZ, 2, 2);
            const tsResult = CircuitAttributeHandler.extractStringAttribute(sampleMRZ, 2, 2);
            expect(contractResult).to.equal(tsResult);
            expect(contractResult).to.equal("U");
        });
    });
});