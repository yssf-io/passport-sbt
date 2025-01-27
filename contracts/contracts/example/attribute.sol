// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import "../libraries/Formatter.sol";
import "../libraries/CircuitAttributeHandler.sol";

contract Attribute {

    enum Dg1AttributeType {
        ISSUING_STATE,
        NAME,
        PASSPORT_NUMBER,
        NATIONALITY,
        DATE_OF_BIRTH,
        GENDER,
        EXPIRY_DATE,
        OLDER_THAN,
        OFAC
    }

    struct Dg1Attributes {
        string issuingState;
        string name;
        string passportNumber;
        string nationality;
        string dateOfBirth;
        string gender;
        string expiryDate;
        uint256 olderThan;
        uint256 ofac;
    }

    function getReadableDg1Attributes(
        uint256[3] memory revealedDataPacked,
        Dg1AttributeType[] memory attributeTypes
    )
        public
        view
        returns (Dg1Attributes memory) 
    {   
        
        bytes memory charcodes = Formatter.fieldElementsToBytes(
            revealedDataPacked
        );

        Dg1Attributes memory attrs;

        for (uint256 i = 0; i < attributeTypes.length; i++) {
            Dg1AttributeType attr = attributeTypes[i];
            if (attr == Dg1AttributeType.ISSUING_STATE) {
                attrs.issuingState = CircuitAttributeHandler.getIssuingState(charcodes);
            } else if (attr == Dg1AttributeType.NAME) {
                attrs.name = CircuitAttributeHandler.getName(charcodes);
            } else if (attr == Dg1AttributeType.PASSPORT_NUMBER) {
                attrs.passportNumber = CircuitAttributeHandler.getPassportNumber(charcodes);
            } else if (attr == Dg1AttributeType.NATIONALITY) {
                attrs.nationality = CircuitAttributeHandler.getNationality(charcodes);
            } else if (attr == Dg1AttributeType.DATE_OF_BIRTH) {
                attrs.dateOfBirth = CircuitAttributeHandler.getDateOfBirth(charcodes);
            } else if (attr == Dg1AttributeType.GENDER) {
                attrs.gender = CircuitAttributeHandler.getGender(charcodes);
            } else if (attr == Dg1AttributeType.EXPIRY_DATE) {
                attrs.expiryDate = CircuitAttributeHandler.getExpiryDate(charcodes);
            } else if (attr == Dg1AttributeType.OLDER_THAN) {
                attrs.olderThan = CircuitAttributeHandler.getOlderThan(charcodes);
            } else if (attr == Dg1AttributeType.OFAC) {
                attrs.ofac = CircuitAttributeHandler.getOfac(charcodes);
            }
        }

        return attrs;
    }
}