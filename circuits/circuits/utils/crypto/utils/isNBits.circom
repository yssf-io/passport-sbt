pragma circom 2.1.6;

include "circomlib/circuits/bitify.circom";

/// @title isNBits
/// @notice Checks whether an input number can be represented using at most `n` bits.
/// @param n The maximum number of bits allowed for the input value.
/// @input in The integer input to be checked.
template isNBits(n) { 
    signal input in;

    component n2b = Num2Bits(254);
    n2b.in <== in;

    signal check[254 - n];
    check[0] <== n2b.out[n];

    for (var i = n + 1; i < 254; i++) {
        check[i - n] <== check[i - n - 1] + n2b.out[i];
    }

    check[254 - n - 1] === 0;
}