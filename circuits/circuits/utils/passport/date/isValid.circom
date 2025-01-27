pragma circom 2.1.9;

include "circomlib/circuits/comparators.circom";
include "circomlib/circuits/bitify.circom";
include "./dateIsLess.circom";

/// @title IsValid
/// @notice Verifies if the passport is valid at the current date
/// @param currDate Current date: YYMMDD — number
/// @param validityDateASCII Validity date: YYMMDD — ASCII
/// @output out Result of the comparison
/// @dev output is constrained

template IsValid() {
    signal input currDate[6];
    signal input validityDateASCII[6];
    
    signal validityDateNum[6];
    signal ASCII_rotation <== 48;
    
    for (var i=0; i<6; i++) {
        validityDateNum[i] <== validityDateASCII[i] - ASCII_rotation;
    }

    signal TEN <== 10;
    signal CENTURY <== 100;

    signal currDateYear <== currDate[0] * TEN + currDate[1];
    signal validityYear <== validityDateNum[0] * TEN + validityDateNum[1];

    component is_valid = DateIsLess();
    is_valid.secondYear  <== validityDateNum[0] * TEN + validityDateNum[1];
    is_valid.secondMonth <== validityDateNum[2] * TEN + validityDateNum[3];
    is_valid.secondDay   <== validityDateNum[4] * TEN + validityDateNum[5];

    is_valid.firstYear <== currDateYear;
    is_valid.firstMonth <== currDate[2] * TEN + currDate[3];
    is_valid.firstDay <== currDate[4] * TEN + currDate[5];

    1 === is_valid.out;
}
