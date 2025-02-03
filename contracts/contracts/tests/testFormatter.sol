// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import "../libraries/Formatter.sol";

contract TestFormatter {
    // tested
    function testFormatName(string memory input) external pure returns (string[] memory) {
        return Formatter.formatName(input);
    }

    // tested
    function testFormatDate(string memory date) external pure returns (string memory) {
        return Formatter.formatDate(date);
    }

    // tested
    function testNumAsciiToUint(uint256 numAscii) external pure returns (uint256) {
        return Formatter.numAsciiToUint(numAscii);
    }

    // tested
    function testFieldElementsToBytes(uint256[3] memory publicSignals) external pure returns (bytes memory) {
        return Formatter.fieldElementsToBytes(publicSignals);
    }

    // tested
    function testExtractForbiddenCountriesFromPacked(uint256 publicSignal) 
        external 
        pure 
        returns (string[10] memory) 
    {
        return Formatter.extractForbiddenCountriesFromPacked(publicSignal);
    }

    function testProofDateToUnixTimestamp(uint256[6] memory dateNum) external pure returns (uint256) {
        return Formatter.proofDateToUnixTimestamp(dateNum);
    }

    // tested
    function testDateToUnixTimestamp(string memory date) external pure returns (uint256) {
        return Formatter.dateToUnixTimestamp(date);
    }

    // tested
    function testSubstring(string memory str, uint startIndex, uint endIndex) external pure returns (string memory) {
        return Formatter.substring(str, startIndex, endIndex);
    }

    // tested
    function testParseDatePart(string memory value) external pure returns (uint) {
        return Formatter.parseDatePart(value);
    }

    function testToTimestamp(uint256 year, uint256 month, uint256 day) external pure returns (uint) {
        return Formatter.toTimestamp(year, month, day);
    }

    // tested
    function testIsLeapYear(uint256 year) external pure returns (bool) {
        return Formatter.isLeapYear(year);
    }
}
