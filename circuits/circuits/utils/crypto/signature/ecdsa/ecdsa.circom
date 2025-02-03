pragma circom  2.1.6;

include "../../ec/curve.circom";
include "../../ec/get.circom";
include "../../bigInt/bigInt.circom";

/// @title verifyECDSABits
/// @notice Verifies an ECDSA signature using a specified curve and hashing algorithm
/// @param CHUNK_SIZE The size of each chunk in bits, used for representing large integers
/// @param CHUNK_NUMBER The number of chunks used to represent each large integer
/// @param A The coefficient `a` of the elliptic curve equation
/// @param B The coefficient `b` of the elliptic curve equation
/// @param P The prime number defining the finite field for the elliptic curve
/// @param ALGO The size of the hashed message in bits, corresponding to the chosen hashing algorithm
/// @input pubkey Public key used for verification, represented as a 2D array of chunks
/// @input signature Signature to verify, represented as a 2D array of chunks
/// @input hashed The hashed message being verified, represented as an array of bits with length `ALGO`
template verifyECDSABits(CHUNK_SIZE, CHUNK_NUMBER, A, B, P, ALGO){
    signal input pubkey[2][CHUNK_NUMBER];
    signal input signature[2][CHUNK_NUMBER];
    signal input hashed[ALGO];

    signal hashedChunked[CHUNK_NUMBER];
    
    component bits2Num[CHUNK_NUMBER];
    for (var i = 0; i < CHUNK_NUMBER; i++) {
        bits2Num[i] = Bits2Num(CHUNK_SIZE);
        for (var j = 0; j < CHUNK_SIZE; j++) {
            bits2Num[i].in[CHUNK_SIZE - 1 - j] <== hashed[i * CHUNK_SIZE + j];
        }
        hashedChunked[CHUNK_NUMBER - 1 - i] <== bits2Num[i].out;
    }

    signal one[CHUNK_NUMBER]; 
    one[0] <== 1;
    for (var i = 1; i < CHUNK_NUMBER; i++){
        one[i] <== 0; 
    }
    
    component getOrder = EllipicCurveGetOrder(CHUNK_SIZE,CHUNK_NUMBER, A, B, P);
    signal order[CHUNK_NUMBER];
    order <== getOrder.order;

    // check if 1 <= r < order
    component rangeChecks[2]; 
    rangeChecks[0] = BigRangeCheck(CHUNK_SIZE, CHUNK_NUMBER);
    rangeChecks[0].value <== signature[0]; 
    rangeChecks[0].lowerBound <== one;
    rangeChecks[0].upperBound <== order;
    rangeChecks[0].out === 1;

    //check if 1 <= s < order
    rangeChecks[1] = BigRangeCheck(CHUNK_SIZE, CHUNK_NUMBER);
    rangeChecks[1].value <== signature[1]; 
    rangeChecks[1].lowerBound <== one;
    rangeChecks[1].upperBound <== order;
    rangeChecks[1].out === 1;
    
    // s_inv = s ^ -1 mod n
    signal sinv[CHUNK_NUMBER];
    
    component modInv = BigModInv(CHUNK_SIZE, CHUNK_NUMBER);
    
    modInv.in <== signature[1];
    modInv.modulus <== order;
    modInv.out ==> sinv;
    
    // (s ^ -1 mod n) * h mod n
    component mult = BigMultModP(CHUNK_SIZE, CHUNK_NUMBER, CHUNK_NUMBER, CHUNK_NUMBER);
    mult.in1 <== sinv;
    mult.in2 <== hashedChunked;
    mult.modulus <== order;

    // (s ^ -1 mod n) * r mod n
    component mult2 = BigMultModP(CHUNK_SIZE, CHUNK_NUMBER, CHUNK_NUMBER, CHUNK_NUMBER);
    mult2.in1 <== sinv;
    mult2.in2 <== signature[0];
    mult2.modulus <== order;
    
    // h * s_inv * G
    component scalarMult1 = EllipicCurveScalarGeneratorMult(CHUNK_SIZE, CHUNK_NUMBER, A, B, P);
    scalarMult1.scalar <== mult.mod;
    
    // r * s_inv * (x, y)
    component scalarMult2 = EllipticCurveScalarMult(CHUNK_SIZE, CHUNK_NUMBER, A, B, P, 4);
    scalarMult2.scalar <== mult2.mod;
    scalarMult2.in <== pubkey;

    // (x1, y1) = h * s_inv * G + r * s_inv * (x, y)
    component add = EllipticCurveAdd(CHUNK_SIZE, CHUNK_NUMBER, A, B, P);
    add.in1 <== scalarMult1.out;
    add.in2 <== scalarMult2.out;

    component addModN = BigMultModP(CHUNK_SIZE, CHUNK_NUMBER, CHUNK_NUMBER, CHUNK_NUMBER);
    addModN.in1 <== add.out[0];
    addModN.in2 <== one;
    addModN.modulus <== order;
    
    // x1 === r
    for (var i = 0; i < CHUNK_NUMBER; i++){
        addModN.mod[i] === signature[0][i];
    }
}