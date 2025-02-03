// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/**
 * @title Formatter Library
 * @notice A library providing utility functions to format names, dates, and encode data.
 */
library Formatter {
    error InvalidDateLength();
    error InvalidAsciiCode();

    uint256 constant MAX_FORBIDDEN_COUNTRIES_LIST_LENGTH = 10;

    /**
     * @notice Formats a full name string into first name(s) and last name.
     * @dev The input is expected to contain a last name, followed by a "<<" separator and then first name(s).
     *      The returned array contains the first names at index 0 and the last name at index 1.
     * @param input The input string structured as "lastName<<firstName(s)".
     * @return names An array of two strings: [firstName(s), lastName].
     */
    function formatName(
        string memory input
    ) internal pure returns (string[] memory) {
        bytes memory inputBytes = bytes(input);
        bytes memory firstNameBytes;
        bytes memory lastNameBytes;
        string[] memory names = new string[](2);

        uint i = 0;
        // Extract last name
        while (i < inputBytes.length && inputBytes[i] != "<") {
            lastNameBytes = abi.encodePacked(lastNameBytes, inputBytes[i]);
            i++;
        }

        // Skip the separator "<<".
        i += 2;

        // Extract first names.
        while (i < inputBytes.length) {
            if (inputBytes[i] == "<") {
                if (i + 1 < inputBytes.length && inputBytes[i + 1] == "<") {
                    break;
                }
                firstNameBytes = abi.encodePacked(firstNameBytes, " ");
            } else {
                firstNameBytes = abi.encodePacked(
                    firstNameBytes,
                    inputBytes[i]
                );
            }
            i++;
        }

        names[0] = string(firstNameBytes);
        names[1] = string(lastNameBytes);
        return names;
    }

    /**
     * @notice Formats a compact date string into a human-readable date.
     * @dev Expects the input date string to have exactly 6 characters in YYMMDD format.
     *      Returns the date in "DD-MM-YY" format.
     * @param date A string representing the date in YYMMDD format.
     * @return A formatted date string in the format "DD-MM-YY".
     */
    function formatDate(
        string memory date
    ) internal pure returns (string memory) {
        // Ensure the date string is the correct length.
        if (bytes(date).length != 6) {
            revert InvalidDateLength();
        }

        string memory year = substring(date, 0, 2);
        string memory month = substring(date, 2, 4);
        string memory day = substring(date, 4, 6);

        return string(abi.encodePacked(day, "-", month, "-", year));
    }

    /**
     * @notice Converts an ASCII numeral code to its corresponding unsigned integer.
     * @dev The input must represent an ASCII code for digits (0-9), i.e. between 48 and 57.
     *      Reverts with InvalidAsciiCode if the input is out of range.
     * @param numAscii The ASCII code of a digit character.
     * @return The numeric value (0-9) corresponding to the ASCII code.
     */
    function numAsciiToUint(uint256 numAscii) internal pure returns (uint256) {
        if (numAscii < 48 || numAscii > 57) {
            revert InvalidAsciiCode();
        }
        return (numAscii - 48);
    }

    /**
     * @notice Converts an array of three field elements into a bytes representation.
     * @dev Each element is converted into a specific number of bytes: 31, 31, and 29 respectively.
     * @param publicSignals An array of three unsigned integers representing field elements.
     * @return bytesArray A bytes array of total length 91 that encodes the three field elements.
     */
    function fieldElementsToBytes(
        uint256[3] memory publicSignals
    ) internal pure returns (bytes memory) {
        uint8[3] memory bytesCount = [31, 31, 29];
        bytes memory bytesArray = new bytes(91);

        uint256 index = 0;
        for (uint256 i = 0; i < 3; i++) {
            uint256 element = publicSignals[i];
            for (uint8 j = 0; j < bytesCount[i]; j++) {
                bytesArray[index++] = bytes1(uint8(element & 0xff));
                element = element >> 8;
            }
        }
        return bytesArray;
    }

    /**
     * @notice Extracts forbidden country codes from a packed uint256.
     * @dev Each forbidden country is represented by 3 bytes in the packed data.
     *      The function extracts up to MAX_FORBIDDEN_COUNTRIES_LIST_LENGTH forbidden countries.
     * @param publicSignal A packed uint256 containing encoded forbidden country data.
     * @return forbiddenCountries An array of strings representing the forbidden country codes.
     */
    function extractForbiddenCountriesFromPacked(
        uint256 publicSignal
    )
        internal
        pure
        returns (
            string[MAX_FORBIDDEN_COUNTRIES_LIST_LENGTH] memory forbiddenCountries
        )
    {
        for (uint256 j = 0; j < MAX_FORBIDDEN_COUNTRIES_LIST_LENGTH; j++) {
            uint256 byteIndex = j * 3;

            uint256 shift = byteIndex * 8;
            uint256 mask = 0xFFFFFF;
            uint256 packedData = (publicSignal >> shift) & mask;
            forbiddenCountries[j] = string(abi.encodePacked(uint24(packedData)));
        }

        return forbiddenCountries;
    }

    /**
     * @notice Converts an array of 6 numerical values representing a date into a Unix timestamp.
     * @dev Each element in the dateNum array is taken modulo 10, converted to its ASCII digit, 
     *      and concatenated to form a date string in YYMMDD format. This string is then converted 
     *      into a Unix timestamp using dateToUnixTimestamp.
     * @param dateNum An array of 6 unsigned integers representing a date in YYMMDD format.
     * @return timestamp The Unix timestamp corresponding to the provided date.
     */
    function proofDateToUnixTimestamp(
        uint256[6] memory dateNum
    ) internal pure returns (uint256) {
        string memory date = "";
        for (uint256 i = 0; i < 6; i++) {
            date = string(
                abi.encodePacked(date, bytes1(uint8(48 + (dateNum[i] % 10))))
            );
        }
        uint256 currentTimestamp = dateToUnixTimestamp(date);
        return currentTimestamp;
    }

    /**
     * @notice Converts a date string in YYMMDD format into a Unix timestamp.
     * @dev Parses the date string by extracting year, month, and day components using substring,
     *      converts each component to an integer, and then computes the timestamp via toTimestamp.
     *      Reverts if the input string is not exactly 6 characters long.
     * @param date A 6-character string representing the date in YYMMDD format.
     * @return timestamp The Unix timestamp corresponding to the input date.
     */
    function dateToUnixTimestamp(
        string memory date
    ) internal pure returns (uint256) {
        if (bytes(date).length != 6) {
            revert InvalidDateLength();
        }

        uint256 year = parseDatePart(substring(date, 0, 2)) + 2000;
        uint256 month = parseDatePart(substring(date, 2, 4));
        uint256 day = parseDatePart(substring(date, 4, 6));

        return toTimestamp(year, month, day);
    }

    /**
     * @notice Extracts a substring from a given string.
     * @dev Returns the substring from startIndex (inclusive) to endIndex (exclusive).
     * @param str The input string.
     * @param startIndex The starting index of the substring (inclusive).
     * @param endIndex The ending index of the substring (exclusive).
     * @return The resulting substring.
     */
    function substring(
        string memory str,
        uint startIndex,
        uint endIndex
    ) internal pure returns (string memory) {
        bytes memory strBytes = bytes(str);
        bytes memory result = new bytes(endIndex - startIndex);

        for (uint i = startIndex; i < endIndex; i++) {
            result[i - startIndex] = strBytes[i];
        }

        return string(result);
    }

    /**
     * @notice Parses a numeric string and returns its unsigned integer representation.
     * @dev Assumes the input string contains only numeric characters.
     * @param value The string representing a number.
     * @return result The parsed unsigned integer.
     */
    function parseDatePart(string memory value) internal pure returns (uint) {
        bytes memory tempEmptyStringTest = bytes(value);
        if (tempEmptyStringTest.length == 0) {
            return 0;
        }

        uint digit;
        uint result;
        for (uint i = 0; i < tempEmptyStringTest.length; i++) {
            digit = uint(uint8(tempEmptyStringTest[i])) - 48; // '0' is 48 in ASCII
            result = result * 10 + digit;
        }
        return result;
    }

    /**
     * @notice Converts a specific date into a Unix timestamp.
     * @dev Calculates the timestamp by summing the number of days for years, months, and days since January 1, 1970.
     *      Takes leap years into account during the calculation.
     * @param year The full year (e.g., 2023).
     * @param month The month (1-12).
     * @param day The day of the month.
     * @return timestamp The Unix timestamp corresponding to the given date.
     */
    function toTimestamp(
        uint256 year,
        uint256 month,
        uint256 day
    ) internal pure returns (uint timestamp) {
        uint16 i;

        // Year.
        for (i = 1970; i < year; i++) {
            if (isLeapYear(i)) {
                timestamp += 366 days;
            } else {
                timestamp += 365 days;
            }
        }

        // Month.
        uint8[12] memory monthDayCounts;
        monthDayCounts[0] = 31;
        if (isLeapYear(year)) {
            monthDayCounts[1] = 29;
        } else {
            monthDayCounts[1] = 28;
        }
        monthDayCounts[2] = 31;
        monthDayCounts[3] = 30;
        monthDayCounts[4] = 31;
        monthDayCounts[5] = 30;
        monthDayCounts[6] = 31;
        monthDayCounts[7] = 31;
        monthDayCounts[8] = 30;
        monthDayCounts[9] = 31;
        monthDayCounts[10] = 30;
        monthDayCounts[11] = 31;

        for (i = 1; i < month; i++) {
            timestamp += monthDayCounts[i - 1] * 1 days;
        }

        // Day.
        timestamp += (day - 1) * 1 days;

        return timestamp;
    }

    /**
     * @notice Checks whether a given year is a leap year.
     * @param year The year to check.
     * @return True if the year is a leap year, otherwise false.
     */
    function isLeapYear(uint256 year) internal pure returns (bool) {
        if (year % 4 != 0) {
            return false;
        } else if (year % 100 != 0) {
            return true;
        } else if (year % 400 != 0) {
            return false;
        } else {
            return true;
        }
    }

}
