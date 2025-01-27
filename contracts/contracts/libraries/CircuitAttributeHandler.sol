// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import "../interfaces/IVcAndDiscloseCircuitVerifier.sol";
import "../constants/CircuitConstants.sol";
import "./Formatter.sol";

library CircuitAttributeHandler {

    error INSUFFICIENT_CHARCODE_LEN();

    // Define constant start and end positions for each attribute
    uint256 private constant ISSUING_STATE_START = 2;
    uint256 private constant ISSUING_STATE_END = 4;

    uint256 private constant NAME_START = 5;
    uint256 private constant NAME_END = 43;

    uint256 private constant PASSPORT_NUMBER_START = 44;
    uint256 private constant PASSPORT_NUMBER_END = 52;

    uint256 private constant NATIONALITY_START = 54;
    uint256 private constant NATIONALITY_END = 56;

    uint256 private constant DATE_OF_BIRTH_START = 57;
    uint256 private constant DATE_OF_BIRTH_END = 62;

    uint256 private constant GENDER_START = 64;
    uint256 private constant GENDER_END = 64;

    uint256 private constant EXPIRY_DATE_START = 65;
    uint256 private constant EXPIRY_DATE_END = 70;

    uint256 private constant OLDER_THAN_START = 88;
    uint256 private constant OLDER_THAN_END = 89;

    uint256 private constant OFAC_START = 90;
    uint256 private constant OFAC_END = 90;

    function getIssuingState(bytes memory charcodes) internal pure returns (string memory) {
        return extractStringAttribute(charcodes, ISSUING_STATE_START, ISSUING_STATE_END);
    }

    function getName(bytes memory charcodes) internal pure returns (string memory) {
        return extractStringAttribute(charcodes, NAME_START, NAME_END);
    }

    function getPassportNumber(bytes memory charcodes) internal pure returns (string memory) {
        return extractStringAttribute(charcodes, PASSPORT_NUMBER_START, PASSPORT_NUMBER_END);
    }

    function getNationality(bytes memory charcodes) internal pure returns (string memory) {
        return extractStringAttribute(charcodes, NATIONALITY_START, NATIONALITY_END);
    }

    function getDateOfBirth(bytes memory charcodes) internal pure returns (string memory) {
        return extractStringAttribute(charcodes, DATE_OF_BIRTH_START, DATE_OF_BIRTH_END);
    }

    function getGender(bytes memory charcodes) internal pure returns (string memory) {
        return extractStringAttribute(charcodes, GENDER_START, GENDER_END);
    }

    function getExpiryDate(bytes memory charcodes) internal pure returns (string memory) {
        return extractStringAttribute(charcodes, EXPIRY_DATE_START, EXPIRY_DATE_END);
    }

    function getOlderThan(bytes memory charcodes) internal pure returns (uint256) {
        return extractOlderThan(charcodes);
    }

    function getOfac(bytes memory charcodes) internal pure returns (uint256) {
        return extractOfac(charcodes);
    }

    function compareOlderThan(
        bytes memory charcodes,
        uint256 olderThan
    ) internal pure returns (bool) {
        return extractOlderThan(charcodes) >= olderThan;
    }

    function compareOfac(
        bytes memory charcodes
    ) internal pure returns (bool) {
        return extractOfac(charcodes) == 1;
    }

    function extractStringAttribute(bytes memory charcodes, uint256 start, uint256 end) internal pure returns (string memory) {
        if (charcodes.length <= end) {
            revert INSUFFICIENT_CHARCODE_LEN();
        }
        bytes memory attributeBytes = new bytes(end - start + 1);
        for (uint256 i = start; i <= end; i++) {
            attributeBytes[i - start] = charcodes[i];
        }
        return string(attributeBytes);
    }

    function extractOlderThan(    
        bytes memory charcodes
    ) internal pure returns (uint256) {
        return Formatter.numAsciiToUint(uint8(charcodes[OLDER_THAN_START]))*10
            + Formatter.numAsciiToUint(uint8(charcodes[OLDER_THAN_START + 1]));
    }

    function extractOfac(
        bytes memory charcodes
    ) internal pure returns (uint256) {
        return uint8(charcodes[OFAC_START]);
    }
}