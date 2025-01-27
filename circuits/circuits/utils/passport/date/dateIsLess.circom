pragma circom 2.1.9;

include "circomlib/circuits/comparators.circom";

/// @title DateIsLess
/// @notice compares two dates in the YMD numeric format
/// @param firstDay day of the first date
/// @param secondDay day of the second date
/// @param firstMonth month of the first date
/// @param secondMonth month of the second date
/// @param firstYear year of the first date
/// @param secondYear year of the second date
/// @output out Result of the comparison
/// @dev output is not constrained — verifier has to handle this check

template DateIsLess() {
    signal input firstDay;
    signal input secondDay;

    signal input firstMonth;
    signal input secondMonth;

    signal input firstYear;
    signal input secondYear;

    signal output out;

    component yearLess = LessThan(8);
    yearLess.in[0] <== firstYear;
    yearLess.in[1] <== secondYear;
    signal isYearLess <== yearLess.out;

    component monthLess = LessThan(8);
    monthLess.in[0] <== firstMonth;
    monthLess.in[1] <== secondMonth;
    signal isMonthLess <== monthLess.out;

    component dayLess = LessThan(8);
    dayLess.in[0] <== firstDay;
    dayLess.in[1] <== secondDay;
    signal isDayLess <== dayLess.out;

    // ----

    component yearEqual = IsEqual();
    yearEqual.in[0] <== firstYear;
    yearEqual.in[1] <== secondYear;
    signal isYearEqual <== yearEqual.out;

    component monthEqual = IsEqual();
    monthEqual.in[0] <== firstMonth;
    monthEqual.in[1] <== secondMonth;
    signal isMonthEqual <== monthEqual.out;

    // ----------
    signal isLess1 <== isYearLess;
    signal isLess2 <== (isYearEqual * isMonthLess);
    signal temp    <== isYearEqual * isMonthEqual;
    signal isLess3 <== (temp * isDayLess);

    component greaterThen = GreaterThan(3);
    greaterThen.in[0] <== isLess1 + isLess2 + isLess3;
    greaterThen.in[1] <== 0;

    out <== greaterThen.out;
}