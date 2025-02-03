pragma circom 2.1.6;

include "circomlib/circuits/comparators.circom";
include "circomlib/circuits/bitify.circom";
include "./bigIntFunc.circom";
include "./bigIntOverflow.circom";
include "../int/arithmetic.circom";

// What BigInt in this lib means
// We represent big number as array of chunks with some shunk_size (will be explained later) 
// for this example we will use N for number, n for chunk size and k for chunk_number:
// N[k];
// Number can be calculated by this formula:
// N = N[0] * 2 ** (0 * n) + N[1] * 2 ** (1 * n) + ... + N[k - 1] * 2 ** ((k-1) * n)
// By overflow we mean situation where N[i] >= 2 ** n
// Without overflow every number has one and only one representation
// To reduce overflow we must leave N[i] % 2 ** n for N[i] and add N[i] // 2 ** n to N[i + 1]
// If u want to do many operation in a row, it is better to use overflow operations from "./bigIntOverflow" and then just reduce overflow from result

// -------------------------------------------------------------------------------------------------------------------------------------------------

// Get in1 * in2 % modulus and in1 * in2 // modulus
template BigMultModP(CHUNK_SIZE, CHUNK_NUMBER_GREATER, CHUNK_NUMBER_LESS, CHUNK_NUMBER_MODULUS){
    signal input in1[CHUNK_NUMBER_GREATER];
    signal input in2[CHUNK_NUMBER_LESS];
    signal input modulus[CHUNK_NUMBER_MODULUS];

    var CHUNK_NUMBER_BASE = CHUNK_NUMBER_GREATER + CHUNK_NUMBER_LESS;
    var CHUNK_NUMBER_DIV = CHUNK_NUMBER_BASE - CHUNK_NUMBER_MODULUS + 1;

    signal output div[CHUNK_NUMBER_DIV];
    signal output mod[CHUNK_NUMBER_MODULUS];
    
    component mult = BigMultOverflow(CHUNK_SIZE, CHUNK_NUMBER_GREATER, CHUNK_NUMBER_LESS);
    mult.in1 <== in1;
    mult.in2 <== in2;

    var reduced[200] = reduce_overflow_dl(CHUNK_SIZE, CHUNK_NUMBER_BASE - 1, CHUNK_NUMBER_BASE, mult.out);
    var long_division[2][200] = long_div_dl(CHUNK_SIZE, CHUNK_NUMBER_MODULUS, CHUNK_NUMBER_DIV - 1, reduced, modulus);
    
    for (var i = 0; i < CHUNK_NUMBER_DIV; i++){
        div[i] <-- long_division[0][i];
    }

    component modChecks[CHUNK_NUMBER_MODULUS];
    for (var i = 0; i < CHUNK_NUMBER_MODULUS; i++){
        mod[i] <-- long_division[1][i];
        // Check to avoid negative numbers
        modChecks[i] = Num2Bits(CHUNK_SIZE);
        modChecks[i].in <== mod[i];

    }
    
    component greaterThan = BigGreaterThan(CHUNK_SIZE, CHUNK_NUMBER_MODULUS);
    
    greaterThan.in[0] <== modulus;
    greaterThan.in[1] <== mod;
    greaterThan.out === 1;
    
    component mult2;
    if (CHUNK_NUMBER_DIV >= CHUNK_NUMBER_MODULUS){
        mult2 = BigMultNonEqualOverflow(CHUNK_SIZE, CHUNK_NUMBER_DIV, CHUNK_NUMBER_MODULUS);
        
        mult2.in1 <== div;
        mult2.in2 <== modulus;
    } else {
        mult2 = BigMultNonEqualOverflow(CHUNK_SIZE, CHUNK_NUMBER_MODULUS, CHUNK_NUMBER_DIV);
        
        mult2.in2 <== div;
        mult2.in1 <== modulus;
    }
    
    component isZero = BigIntIsZero(CHUNK_SIZE, CHUNK_SIZE * 2 + log_ceil(CHUNK_NUMBER_MODULUS + CHUNK_NUMBER_DIV - 1), CHUNK_NUMBER_BASE - 1);
    for (var i = 0; i < CHUNK_NUMBER_MODULUS; i++) {
        isZero.in[i] <== mult.out[i] - mult2.out[i] - mod[i];
    }
    for (var i = CHUNK_NUMBER_MODULUS; i < CHUNK_NUMBER_BASE - 1; i++) {
        isZero.in[i] <== mult.out[i] - mult2.out[i];
    }
}

// in[0] < in[1]
template BigLessThan(CHUNK_SIZE, CHUNK_NUMBER){
    signal input in[2][CHUNK_NUMBER];
    
    signal output out;
    
    component lessThan[CHUNK_NUMBER];
    component isEqual[CHUNK_NUMBER - 1];
    signal result[CHUNK_NUMBER - 1];
    for (var i = 0; i < CHUNK_NUMBER; i++){
        lessThan[i] = LessThan(CHUNK_SIZE);
        lessThan[i].in[0] <== in[0][i];
        lessThan[i].in[1] <== in[1][i];
        
        if (i != 0){
            isEqual[i - 1] = IsEqual();
            isEqual[i - 1].in[0] <== in[0][i];
            isEqual[i - 1].in[1] <== in[1][i];
        }
    }
    
    for (var i = 1; i < CHUNK_NUMBER; i++){
        if (i == 1){
            result[i - 1] <== lessThan[i].out + isEqual[i - 1].out * lessThan[i - 1].out;
        } else {
            result[i - 1] <== lessThan[i].out + isEqual[i - 1].out * result[i - 2];
        }
    }
    out <== result[CHUNK_NUMBER - 2];
}

// in[0] <= in[1]
template BigLessEqThan(CHUNK_SIZE, CHUNK_NUMBER){
    signal input in[2][CHUNK_NUMBER];
    
    signal output out;
    
    component lessThan[CHUNK_NUMBER];
    component isEqual[CHUNK_NUMBER];
    signal result[CHUNK_NUMBER];
    for (var i = 0; i < CHUNK_NUMBER; i++){
        lessThan[i] = LessThan(CHUNK_SIZE);
        lessThan[i].in[0] <== in[0][i];
        lessThan[i].in[1] <== in[1][i];
        
        isEqual[i] = IsEqual();
        isEqual[i].in[0] <== in[0][i];
        isEqual[i].in[1] <== in[1][i];
    }
    
    for (var i = 0; i < CHUNK_NUMBER; i++){
        if (i == 0){
            result[i] <== lessThan[i].out + isEqual[i].out;
        } else {
            result[i] <== lessThan[i].out + isEqual[i].out * result[i - 1];
        }
    }
    
    out <== result[CHUNK_NUMBER - 1];
}

// in[0] > in[1]
template BigGreaterThan(CHUNK_SIZE, CHUNK_NUMBER){
    signal input in[2][CHUNK_NUMBER];
    
    signal output out;
    
    component lessEqThan = BigLessEqThan(CHUNK_SIZE, CHUNK_NUMBER);
    lessEqThan.in <== in;
    out <== 1 - lessEqThan.out;
}

// lowerbound <= value < upperbound
template BigRangeCheck(CHUNK_SIZE, CHUNK_NUMBER) {
    signal input value[CHUNK_NUMBER];
    signal input lowerBound[CHUNK_NUMBER];
    signal input upperBound[CHUNK_NUMBER];

    signal output out;

    component greaterThanLower = BigLessThan(CHUNK_SIZE, CHUNK_NUMBER);
    greaterThanLower.in[0] <== value;
    greaterThanLower.in[1] <== lowerBound;

    component lessThanUpper = BigLessThan(CHUNK_SIZE, CHUNK_NUMBER);
    lessThanUpper.in[0] <== value;
    lessThanUpper.in[1] <== upperBound;

    out <== (1 - greaterThanLower.out) * lessThanUpper.out;
}

// calculates in ^ (-1) % modulus;
// in, modulus has CHUNK_NUMBER
template BigModInv(CHUNK_SIZE, CHUNK_NUMBER) {
    assert(CHUNK_SIZE <= 252);
    signal input in[CHUNK_NUMBER];
    signal input modulus[CHUNK_NUMBER];
    signal output out[CHUNK_NUMBER];
    
    
    var inv[200] = mod_inv_dl(CHUNK_SIZE, CHUNK_NUMBER, in, modulus);
    for (var i = 0; i < CHUNK_NUMBER; i++) {
        out[i] <-- inv[i];
    }
    
    component mult = BigMultModP(CHUNK_SIZE, CHUNK_NUMBER, CHUNK_NUMBER, CHUNK_NUMBER);
    mult.in1 <== in;
    mult.in2 <== out;
    mult.modulus <== modulus;
    
    mult.mod[0] === 1;
    for (var i = 1; i < CHUNK_NUMBER; i++) {
        mult.mod[i] === 0;
    }
}