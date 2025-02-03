import { expect } from "chai";
import { ethers } from "hardhat";
import { TestFormatter } from "../../typechain-types";
import { Formatter } from "../utils/formatter";

describe("Formatter", function () {
    let testFormatter: TestFormatter;

    before(async function () {
        const TestFormatterFactory = await ethers.getContractFactory("TestFormatter");
        testFormatter = await TestFormatterFactory.deploy();
        await testFormatter.waitForDeployment();
    });

    describe("formatName", function () {
        it("should match contract and ts implementation", async function () {
            const input = "DUPONT<<ALPHONSE<HUGHUES<ALBERT<<<";
            const contractResult = await testFormatter.testFormatName(input);
            const tsResult = Formatter.formatName(input);
            expect(contractResult[0]).to.equal(tsResult[0]);
            expect(contractResult[1]).to.equal(tsResult[1]);
            expect(contractResult[0]).to.equal("ALPHONSE HUGHUES ALBERT");
            expect(contractResult[1]).to.equal("DUPONT");
        });

        it("should match contract and ts implementation for single name", async function () {
            const input = "SMITH<<JOHN<<<";
            const contractResult = await testFormatter.testFormatName(input);
            const tsResult = Formatter.formatName(input);
            expect(contractResult[0]).to.equal(tsResult[0]);
            expect(contractResult[1]).to.equal(tsResult[1]);
            expect(contractResult[0]).to.equal("JOHN");
            expect(contractResult[1]).to.equal("SMITH");
        });
    });

    describe("formatDate", function () {
        it("should match contract and ts implementation", async function () {
            const input = "940131";
            const contractResult = await testFormatter.testFormatDate(input);
            const tsResult = Formatter.formatDate(input);
            expect(contractResult).to.equal(tsResult);
            expect(contractResult).to.equal("31-01-94");
        });

        it("should handle errors consistently between contract and ts", async function () {
            const input = "12345";
            await expect(testFormatter.testFormatDate(input))
                .to.be.revertedWithCustomError(testFormatter, "InvalidDateLength");
            expect(() => Formatter.formatDate(input))
                .to.throw("InvalidDateLength");
        });
    });

    describe("numAsciiToUint", function () {
        it("should match contract and ts implementation for valid ASCII numbers", async function () {
            for(let i = 0; i <= 9; i++) {
                const input = 48 + i;
                const contractResult = await testFormatter.testNumAsciiToUint(input);
                const tsResult = Formatter.numAsciiToUint(input);
                expect(contractResult).to.equal(tsResult);
                expect(contractResult).to.equal(i);
            }
        });

        it("should handle errors consistently between contract and ts", async function () {
            const invalidInputs = [47, 58];
            for (const input of invalidInputs) {
                await expect(testFormatter.testNumAsciiToUint(input))
                    .to.be.revertedWithCustomError(testFormatter, "InvalidAsciiCode");
                expect(() => Formatter.numAsciiToUint(input))
                    .to.throw("InvalidAsciiCode");
            }
        });
    });

    describe("fieldElementsToBytes", function () {
        it("should match contract and ts implementation", async function () {
            const input = [123n, 456n, 789n];
            const contractResult = await testFormatter.testFieldElementsToBytes(input);
            const tsResult = toHexString(Formatter.fieldElementsToBytes(input as [bigint, bigint, bigint]));
            expect(contractResult).to.deep.equal(tsResult);
        });

        it("should match contract and ts implementation for zero values", async function () {
            const input = [0n, 0n, 0n];
            const contractResult = await testFormatter.testFieldElementsToBytes(input);
            const tsResult =toHexString(Formatter.fieldElementsToBytes(input as [bigint, bigint, bigint]));
            expect(contractResult).to.deep.equal(tsResult);
        });
    });

    describe("extractForbiddenCountriesFromPacked", function () {
        it("should match contract and ts implementation", async function () {
            const input = "0x414141424242434343";
            const contractResult = await testFormatter.testExtractForbiddenCountriesFromPacked(input);
            const tsResult = Formatter.extractForbiddenCountriesFromPacked(BigInt(input));
            expect(contractResult).to.deep.equal(tsResult);
            expect(contractResult[0]).to.equal("CCC");
            expect(contractResult[1]).to.equal("BBB");
            expect(contractResult[2]).to.equal("AAA");
        });
    });

    describe("proofDateToUnixTimestamp", function () {
        it("should match contract and ts implementation", async function () {
            const testCases = [
                {
                    input: [9, 4, 0, 1, 3, 1],
                    expected: 3915734400n
                },
                {
                    input: [0, 0, 0, 1, 0, 1],
                    expected: 946684800n
                },
                {
                    input: [2, 0, 0, 2, 2, 9],
                    expected: 1582934400n
                }
            ];

            for (const testCase of testCases) {
                const contractResult = await testFormatter.testProofDateToUnixTimestamp(testCase.input);
                const tsResult = Formatter.proofDateToUnixTimestamp(testCase.input);
                expect(contractResult).to.equal(BigInt(tsResult));
                expect(contractResult).to.equal(testCase.expected);
            }
        });
    });

    describe("dateToUnixTimestamp", function () {
        it("should match contract and ts implementation", async function () {
            const testCases = [
                {
                    input: "940131",
                    expected: 3915734400n
                },
                {
                    input: "000101",
                    expected: 946684800n
                }
            ];

            for (const testCase of testCases) {
                const contractResult = await testFormatter.testDateToUnixTimestamp(testCase.input);
                const tsResult = Formatter.dateToUnixTimestamp(testCase.input);
                expect(contractResult).to.equal(BigInt(tsResult));
                expect(contractResult).to.equal(testCase.expected);
            }
        });

        it("should handle errors consistently between contract and ts", async function () {
            const input = "12345";
            await expect(testFormatter.testDateToUnixTimestamp(input))
                .to.be.revertedWithCustomError(testFormatter, "InvalidDateLength");
            expect(() => Formatter.dateToUnixTimestamp(input))
                .to.throw("InvalidDateLength");
        });
    });

    describe("substring", function () {
        it("should match contract and ts implementation", async function () {
            const testCases = [
                { str: "ABCDEF", start: 0, end: 3, expected: "ABC" },
                { str: "ABCDEF", start: 2, end: 4, expected: "CD" },
                { str: "ABCDEF", start: 0, end: 6, expected: "ABCDEF" }
            ];

            for (const testCase of testCases) {
                const contractResult = await testFormatter.testSubstring(
                    testCase.str,
                    testCase.start,
                    testCase.end
                );
                const tsResult = Formatter.substring(
                    testCase.str,
                    testCase.start,
                    testCase.end
                );
                expect(contractResult).to.equal(tsResult);
                expect(contractResult).to.equal(testCase.expected);
            }
        });
    });

    describe("parseDatePart", function () {
        it("should match contract and ts implementation", async function () {
            const testCases = [
                { input: "12", expected: 12 },
                { input: "01", expected: 1 },
                { input: "00", expected: 0 },
                { input: "", expected: 0 }
            ];

            for (const testCase of testCases) {
                const contractResult = await testFormatter.testParseDatePart(testCase.input);
                const tsResult = Formatter.parseDatePart(testCase.input);
                expect(contractResult).to.equal(tsResult);
                expect(contractResult).to.equal(testCase.expected);
            }
        });
    });

    describe("toTimestamp", function () {
        it("should match contract and ts implementation", async function () {
            const testCases = [
                {
                    year: 2000,
                    month: 1,
                    day: 1,
                    expected: 946684800n
                },
                {
                    year: 2020,
                    month: 2,
                    day: 29,
                    expected: 1582934400n
                }
            ];

            for (const testCase of testCases) {
                const contractResult = await testFormatter.testToTimestamp(
                    testCase.year,
                    testCase.month,
                    testCase.day
                );
                const tsResult = Formatter.toTimestamp(
                    testCase.year,
                    testCase.month,
                    testCase.day
                );
                expect(contractResult).to.equal(BigInt(tsResult));
                expect(contractResult).to.equal(testCase.expected);
            }
        });
    });

    describe("isLeapYear", function () {
        it("should match contract and ts implementation", async function () {
            const testCases = [
                { year: 2000, expected: true },
                { year: 2020, expected: true },
                { year: 2100, expected: false },
                { year: 2023, expected: false }
            ];

            for (const testCase of testCases) {
                const contractResult = await testFormatter.testIsLeapYear(testCase.year);
                const tsResult = Formatter.isLeapYear(testCase.year);
                expect(contractResult).to.equal(tsResult);
                expect(contractResult).to.equal(testCase.expected);
            }
        });
    });
});

function toHexString(bytes: Uint8Array): string {
    return '0x' + Array.from(bytes)
        .map(b => b.toString(16).padStart(2, '0'))
        .join('');
}
