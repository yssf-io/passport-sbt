// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import "../interfaces/IVcAndDiscloseCircuitVerifier.sol";
import "../constants/CircuitConstants.sol";
import "./Formatter.sol";

/**
 * @title CircuitAttributeHandler Library
 * @notice Provides functions for extracting and formatting passport attributes from a byte array.
 * @dev Utilizes the Formatter library for converting and formatting specific fields.
 */
library CircuitAttributeHandler {

    /**
     * @dev Reverts when the provided character codes array does not contain enough data to extract an attribute.
     */
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

    /**
     * @notice Retrieves the issuing state from the encoded attribute byte array.
     * @param charcodes The byte array containing passport attribute data.
     * @return A string representing the issuing state.
     */
    function getIssuingState(bytes memory charcodes) internal pure returns (string memory) {
        return extractStringAttribute(charcodes, ISSUING_STATE_START, ISSUING_STATE_END);
    }

    /**
     * @notice Retrieves and formats the name from the encoded attribute byte array.
     * @param charcodes The byte array containing passport attribute data.
     * @return A string array with the formatted name parts.
     */
    function getName(bytes memory charcodes) internal pure returns (string[] memory) {
        return Formatter.formatName(extractStringAttribute(charcodes, NAME_START, NAME_END));
    }

    /**
     * @notice Retrieves the passport number from the encoded attribute byte array.
     * @param charcodes The byte array containing passport attribute data.
     * @return The passport number as a string.
     */
    function getPassportNumber(bytes memory charcodes) internal pure returns (string memory) {
        return extractStringAttribute(charcodes, PASSPORT_NUMBER_START, PASSPORT_NUMBER_END);
    }

    /**
     * @notice Retrieves the nationality from the encoded attribute byte array.
     * @param charcodes The byte array containing passport attribute data.
     * @return The nationality as a string.
     */
    function getNationality(bytes memory charcodes) internal pure returns (string memory) {
        return extractStringAttribute(charcodes, NATIONALITY_START, NATIONALITY_END);
    }

    /**
     * @notice Retrieves and formats the date of birth from the encoded attribute byte array.
     * @param charcodes The byte array containing passport attribute data.
     * @return The formatted date of birth as a string.
     */
    function getDateOfBirth(bytes memory charcodes) internal pure returns (string memory) {
        return Formatter.formatDate(extractStringAttribute(charcodes, DATE_OF_BIRTH_START, DATE_OF_BIRTH_END));
    }

    /**
     * @notice Retrieves the gender from the encoded attribute byte array.
     * @param charcodes The byte array containing passport attribute data.
     * @return The gender as a string.
     */
    function getGender(bytes memory charcodes) internal pure returns (string memory) {
        return extractStringAttribute(charcodes, GENDER_START, GENDER_END);
    }

    /**
     * @notice Retrieves and formats the passport expiry date from the encoded attribute byte array.
     * @param charcodes The byte array containing passport attribute data.
     * @return The formatted passport expiry date as a string.
     */
    function getExpiryDate(bytes memory charcodes) internal pure returns (string memory) {
        return Formatter.formatDate(extractStringAttribute(charcodes, EXPIRY_DATE_START, EXPIRY_DATE_END));
    }

    /**
     * @notice Retrieves the 'older than' age attribute from the encoded attribute byte array.
     * @dev Converts two consecutive numeric ASCII characters to a uint256.
     * @param charcodes The byte array containing passport attribute data.
     * @return The extracted age as a uint256.
     */
    function getOlderThan(bytes memory charcodes) internal pure returns (uint256) {
        return Formatter.numAsciiToUint(uint8(charcodes[OLDER_THAN_START])) * 10
            + Formatter.numAsciiToUint(uint8(charcodes[OLDER_THAN_START + 1]));
    }

    /**
     * @notice Retrieves the OFAC status from the encoded attribute byte array.
     * @param charcodes The byte array containing passport attribute data.
     * @return The OFAC status as a uint256.
     */
    function getOfac(bytes memory charcodes) internal pure returns (uint256) {
        return uint8(charcodes[OFAC_START]);
    }

    /**
     * @notice Compares the extracted 'older than' value with a provided threshold.
     * @param charcodes The byte array containing passport attribute data.
     * @param olderThan The threshold value to compare against.
     * @return True if the extracted age is greater than or equal to the threshold, false otherwise.
     */
    function compareOlderThan(
        bytes memory charcodes,
        uint256 olderThan
    ) internal pure returns (bool) {
        return getOlderThan(charcodes) >= olderThan;
    }

    /**
     * @notice Compares the extracted OFAC value to the expected active status (1).
     * @param charcodes The byte array containing passport attribute data.
     * @return True if the extracted OFAC value equals 1, false otherwise.
     */
    function compareOfac(
        bytes memory charcodes
    ) internal pure returns (bool) {
        return getOfac(charcodes) == 1;
    }

    /**
     * @notice Extracts a substring from a specified range in the byte array.
     * @dev Reverts with INSUFFICIENT_CHARCODE_LEN if the byte array's length is insufficient.
     * @param charcodes The byte array containing the encoded passport attribute.
     * @param start The starting index (inclusive) of the attribute in the byte array.
     * @param end The ending index (inclusive) of the attribute in the byte array.
     * @return The extracted attribute as a string.
     */
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

}