// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

library Formatter {
    error InvalidDateLength();
    error InvalidAsciiCode();

    uint256 constant MAX_FORBIDDEN_COUNTRIES_LIST_LENGTH = 20;

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

        // Skip the separator "<<"
        i += 2;

        // Extract first names
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

    function formatDate(
        string memory date
    ) internal pure returns (string memory) {
        // Ensure the date string is the correct length
        if (bytes(date).length != 6) {
            revert InvalidDateLength();
        }

        string memory year = substring(date, 0, 2);
        string memory month = substring(date, 2, 4);
        string memory day = substring(date, 4, 6);

        return string(abi.encodePacked(day, "-", month, "-", year));
    }

    function numAsciiToUint(uint256 numAscii) internal pure returns (uint256) {
        if (numAscii < 48 || numAscii > 57) {
            revert InvalidAsciiCode();
        }
        return (numAscii - 48);
    }

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

    function extractForbiddenCountriesFromPacked(
        uint256[2] memory publicSignals
    )
        internal
        pure
        returns (
            bytes3[MAX_FORBIDDEN_COUNTRIES_LIST_LENGTH]
                memory forbiddenCountries
        )
    {
        for (uint256 j = 0; j < MAX_FORBIDDEN_COUNTRIES_LIST_LENGTH; j++) {
            uint256 byteIndex = j * 3;

            if (byteIndex + 2 < 32) {
                uint256 shift = byteIndex * 8;
                uint256 mask = 0xFFFFFF;
                uint256 packedData = (publicSignals[0] >> shift) & mask;
                forbiddenCountries[j] = bytes3(uint24(packedData));
            } else if (byteIndex < 32) {
                uint256 bytesFrom0 = 32 - byteIndex;
                uint256 bytesTo1 = 3 - bytesFrom0;

                uint256 shift0 = byteIndex * 8;
                uint256 mask0 = (1 << (bytesFrom0 * 8)) - 1;
                uint256 part0 = (publicSignals[0] >> shift0) & mask0;

                uint256 shift1 = 0;
                uint256 mask1 = (1 << (bytesTo1 * 8)) - 1;
                uint256 part1 = (publicSignals[1] >> shift1) & mask1;

                uint256 combined = (part1 << (bytesFrom0 * 8)) | part0;
                forbiddenCountries[j] = bytes3(uint24(combined));
            } else {
                uint256 byteIndexIn1 = byteIndex - 32;
                uint256 shift = byteIndexIn1 * 8;
                uint256 mask = 0xFFFFFF;
                uint256 packedData = (publicSignals[1] >> shift) & mask;
                forbiddenCountries[j] = bytes3(uint24(packedData));
            }
        }

        return forbiddenCountries;
    }

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

    // Helper function to convert a string to an integer
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

    // Convert date to Unix timestamp
    function toTimestamp(
        uint256 year,
        uint256 month,
        uint256 day
    ) internal pure returns (uint timestamp) {
        uint16 i;

        // Year
        for (i = 1970; i < year; i++) {
            if (isLeapYear(i)) {
                timestamp += 366 days;
            } else {
                timestamp += 365 days;
            }
        }

        // Month
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

        // Day
        timestamp += (day - 1) * 1 days;

        return timestamp;
    }

    // Check if year is a leap year
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

    function formatAge(
        string memory age
    ) internal pure returns (string memory) {
        // if it's an empty two bytes string, just show N/A
        return
            bytes(age).length == 2 &&
                bytes(age)[0] == 0x00 &&
                bytes(age)[1] == 0x00
                ? "N/A"
                : age;
    }
}
