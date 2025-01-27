pragma circom 2.1.9;

include "circomlib/circuits/comparators.circom";
include "circomlib/circuits/bitify.circom";
include "./dateIsLess.circom";

/// @title IsOlderThan
/// @notice Verifies if user is older than the majority at the current date
/// @param majorityASCII Majority user wants to prove he is older than: YY — ASCII
/// @param currDate Current date: YYMMDD — number
/// @param birthDateASCII Birthdate: YYMMDD — ASCII
/// @output out Result of the comparison
/// @dev output is not constrained — verifier has to handle this check

template IsOlderThan() {
    signal input majorityASCII[2];
    signal input currDate[6];
    signal input birthDateASCII[6];
    
    signal birthdateNum[6];
    signal ASCII_rotation <== 48;
    
    for (var i=0; i<6; i++) {
        birthdateNum[i] <== birthDateASCII[i] - ASCII_rotation;
    }

    signal TEN <== 10;
    signal CENTURY <== 100;

    signal currDateYear <== currDate[0] * TEN + currDate[1];
    signal birthYear <== birthdateNum[0] * TEN + birthdateNum[1];

    // assert majority is between 0 and 99 (48-57 in ASCII)
    component lessThan[4];
    for (var i = 0; i < 4; i++) {
        lessThan[i] = LessThan(8);
    }
    lessThan[0].in[0] <== 47;
    lessThan[0].in[1] <== majorityASCII[0];
    lessThan[1].in[0] <== 47;
    lessThan[1].in[1] <== majorityASCII[1];
    lessThan[2].in[0] <== majorityASCII[0];
    lessThan[2].in[1] <== 58;
    lessThan[3].in[0] <== majorityASCII[1];
    lessThan[3].in[1] <== 58;

    signal checkLessThan[4];
    checkLessThan[0] <== lessThan[0].out;
    for (var i = 1; i < 4; i++) {
        checkLessThan[i] <== checkLessThan[i-1] * lessThan[i].out;
    }
    checkLessThan[3] === 1;

    signal majorityNum;
    majorityNum <== ( majorityASCII[0] - 48 ) * TEN + ( majorityASCII[1] - 48 );

    component isPrevCentury = LessThan(8);

    isPrevCentury.in[0] <== currDateYear;
    isPrevCentury.in[1] <== birthYear;

    signal currDateYearNormalized <== currDateYear + isPrevCentury.out * CENTURY;

    component is_older_than = DateIsLess();

    is_older_than.firstYear  <== birthYear + majorityNum;
    is_older_than.firstMonth <== birthdateNum[2] * TEN + birthdateNum[3];
    is_older_than.firstDay   <== birthdateNum[4] * TEN + birthdateNum[5];

    is_older_than.secondYear <== currDateYearNormalized;
    is_older_than.secondMonth <== currDate[2] * TEN + currDate[3];
    is_older_than.secondDay <== currDate[4] * TEN + currDate[5];

    signal output out <== is_older_than.out;
}
