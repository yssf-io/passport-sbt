pragma circom 2.1.6;

include "../../bigInt/bigInt.circom";
include "./mgf1.circom";
include "../../bitify/gates.circom";
include "../../hasher/hash.circom";
include "../FpPowMod.circom";

/*
* RSA-PSS (Probabilistic Signature Scheme) Signature Verification
* ============================================================
*
* This template implements RSA-PSS signature verification according to PKCS#1 v2.2 (RFC 8017).
* https://www.rfc-editor.org/rfc/rfc8017#section-9.1.2
* It verifies that a signature is valid for a given message and public key.
*
* Process Overview:
* 1. Computes s^e mod n where s is the signature, e is public exponent (65537), n is modulus
* 2. Validates the encoded message format
* 3. Extracts the salt and hash from the encoded message
* 4. Verifies the signature using MGF1 mask generation and hash comparison
*
* Parameters:
* - CHUNK_SIZE: Size of each chunk in bits (recommended: 64)
* - CHUNK_NUMBER: Number of chunks in modulus (must be 2^n)
* - SALT_LEN: Salt length in bytes
* - HASH_TYPE: Hash function output size in bits (256/384/512)
* - KEY_LENGTH: RSA key length in bits
*
* Supported Configurations:
* - SHA-512 with 64-byte salt
* - SHA-384 with 48-byte salt
* - SHA-256 with 64-byte salt
* - SHA-256 with 32-byte salt
*
* Inputs:
* - pubkey[CHUNK_NUMBER]: Public key modulus split into chunks
* - signature[CHUNK_NUMBER]: RSA signature split into chunks
* - hashed[HASH_TYPE]: Hash of the original message
*
* Important Notes:
* - CHUNK_NUMBER must be a power of 2 (2^n)
* - Salt length is specified in bytes (not bits)
* - The signature and EM length is bounded by the public key modulus length (KEY_LENGTH). This is because RSA signatures are computed using modular exponentiation with the public key modulus (n)
* - The KEY_LENGTH parameter represents this modulus length in bits.
*/

/// @title RSA-PSS Signature Verification Circuit
/// @notice Verifies RSA-PSS signatures according to PKCS#1 v2.1
/// @dev Implements core RSA-PSS verification logic including MGF1 mask generation
/// @param CHUNK_SIZE Size of each chunk in bits (recommended: 120)
/// @param CHUNK_NUMBER Number of chunks in modulus (must be 2^n)
/// @param SALT_LEN Salt length in bytes
/// @param HASH_TYPE Hash function output size in bits (256/384/512)
/// @param KEY_LENGTH RSA key length in bits
/// @input pubkey The public key modulus split into chunks
/// @input signature The RSA signature split into chunks
/// @input hashed The hash of the original message
template VerifyRsaPss65537Sig(CHUNK_SIZE, CHUNK_NUMBER, SALT_LEN, HASH_TYPE, KEY_LENGTH) {
    assert((HASH_TYPE == 384 && SALT_LEN == 48) || (HASH_TYPE == 256 && SALT_LEN == 64) || (HASH_TYPE == 256 && SALT_LEN == 32) || (HASH_TYPE == 512 && SALT_LEN == 64));

    signal input pubkey[CHUNK_NUMBER]; 
    signal input signature[CHUNK_NUMBER];
    signal input hashed[HASH_TYPE]; 


    var EM_LEN = KEY_LENGTH \ 8; 

    var HASH_LEN = HASH_TYPE \ 8; 
    var SALT_LEN_BITS = SALT_LEN * 8; 
    var EM_LEN_BITS = KEY_LENGTH;
    
    signal eM[EM_LEN];
    signal eMsgInBits[EM_LEN_BITS];

    //computing encoded message
    component bigPow = FpPow65537Mod(CHUNK_SIZE, CHUNK_NUMBER);
    for (var i = 0; i < CHUNK_NUMBER; i++) {
        bigPow.base[i] <== signature[i];
        bigPow.modulus[i] <== pubkey[i];
    }
    
    signal encoded[CHUNK_NUMBER];
    encoded <== bigPow.out;
    
    component num2Bits[CHUNK_NUMBER];

    for (var i = 0; i < CHUNK_NUMBER; i++) {
        num2Bits[i] = Num2Bits(CHUNK_SIZE);
        num2Bits[i].in <== encoded[CHUNK_NUMBER - 1 - i];
        
        for (var j = 0; j < CHUNK_SIZE; j++) {
            var sourcePos = i * CHUNK_SIZE + j;
            var targetPos = sourcePos - (CHUNK_NUMBER * CHUNK_SIZE - EM_LEN_BITS);
            if (targetPos >= 0 && targetPos < EM_LEN_BITS) {
                eMsgInBits[targetPos] <== num2Bits[i].out[CHUNK_SIZE - j - 1];
            }
        }
    }
    
    component bits2Num[EM_LEN];

    for (var i = 0; i < EM_LEN; i++) {
        bits2Num[i] = Bits2Num(8);

        for (var j = 0; j < 8; j++) {
            bits2Num[i].in[7 - j] <== eMsgInBits[i * 8 + j];
        }

        eM[EM_LEN - i - 1] <== bits2Num[i].out;
    }
 
    //should be more than HLEN + SLEN + 2
    assert(EM_LEN >= HASH_LEN + SALT_LEN + 2);
    
    //should end with 0xBC (188 in decimal)
    assert(eM[0] == 188); 
    
    var DB_MASK_LEN = EM_LEN - HASH_LEN - 1;

    signal dbMask[DB_MASK_LEN * 8];
    signal db[DB_MASK_LEN * 8];
    signal salt[SALT_LEN * 8];
    signal maskedDB[(EM_LEN - HASH_LEN - 1) * 8];
    
    for (var i = 0; i < (EM_LEN - HASH_LEN - 1) * 8; i++) {
        maskedDB[i] <== eMsgInBits[i];
    }
    
    signal hash[HASH_LEN * 8];
    
    //inserting hash
    for (var i = 0; i < HASH_TYPE; i++) {
        hash[i] <== eMsgInBits[(EM_LEN_BITS) - HASH_TYPE - 8 + i];
    }
    
    //getting mask
    component MGF1 = Mgf1(HASH_TYPE, HASH_LEN, DB_MASK_LEN);
    for (var i = 0; i < (HASH_TYPE); i++) {
        MGF1.seed[i] <== hash[i];
    }

    for (var i = 0; i < DB_MASK_LEN * 8; i++) {
        dbMask[i] <== MGF1.out[i];
    }

    component xor = Xor2(DB_MASK_LEN * 8);

    for (var i = 0; i < DB_MASK_LEN * 8; i++) {
        xor.in1[i] <== maskedDB[i];
        xor.in2[i] <== dbMask[i];
    }

    for (var i = 0; i < DB_MASK_LEN * 8; i++) {
        //setting the first leftmost byte to 0
        if (i == 0) {
            db[i] <== 0;
        } else {
            db[i] <== xor.out[i];
        }
    }
    
    //inserting salt
    for (var i = 0; i < SALT_LEN_BITS; i++) {
        salt[SALT_LEN_BITS - 1 - i] <== db[(DB_MASK_LEN * 8) - 1 - i];
    }
    
    signal mDash[2048];
    //adding 0s
    for (var i = 0; i < 64; i++) {
        mDash[i] <== 0;
    }

    //adding message hash
    for (var i = 0; i < HASH_LEN * 8; i++) {
        mDash[64 + i] <== hashed[i];
    }

    //adding salt
    for (var i = 0; i < SALT_LEN * 8; i++) {
        mDash[64 + HASH_LEN * 8 + i] <== salt[i];
    }
    
    if (HASH_TYPE == 256 && SALT_LEN == 32) {
        //adding padding
        //len = 64+512 = 576 = 1001000000
        for (var i = 577; i < 1014; i++) {
            mDash[i] <== 0;
        }

        mDash[576] <== 1;
        mDash[1023] <== 0;
        mDash[1022] <== 0;
        mDash[1021] <== 0;
        mDash[1020] <== 0;
        mDash[1019] <== 0;
        mDash[1018] <== 0;
        mDash[1017] <== 1;
        mDash[1016] <== 0;
        mDash[1015] <== 0;
        mDash[1014] <== 1;

        signal mDash256[1024];
        for (var i = 0; i < 1024; i++){
            mDash256[i] <== mDash[i];
        }
        
        //hashing
        component hDash256 = ShaHashChunks(2, HASH_TYPE);
        hDash256.in <== mDash256;

        hDash256.out === hash;
    }

    if (HASH_TYPE == 256 && SALT_LEN == 64) {
        for (var i = 833; i < 1014; i++) {
            mDash[i] <== 0;
        }

        mDash[832] <== 1;
        mDash[1023] <== 0;
        mDash[1022] <== 0;
        mDash[1021] <== 0;
        mDash[1020] <== 0;
        mDash[1019] <== 0;
        mDash[1018] <== 0;
        mDash[1017] <== 1;
        mDash[1016] <== 0;
        mDash[1015] <== 1;
        mDash[1014] <== 1;

        signal mDash256[1024];
        for (var i = 0; i < 1024; i++){
            mDash256[i] <== mDash[i];
        }

        component hDash256 = ShaHashChunks(2, HASH_TYPE);
        hDash256.in <== mDash256;

        hDash256.out === hash;
    }

    if (HASH_TYPE == 384 && SALT_LEN == 48) {        
        //padding
        //len = 64+(48*8)+384 = 832 = 1101000000

        component hDash384 = ShaHashBits(64 + SALT_LEN_BITS + HASH_LEN * 8, 384);
        for (var i = 0; i < 832; i++) {
            hDash384.in[i] <== mDash[i];
        }

        hDash384.out === hash;
    }
    if (HASH_TYPE == 512 && SALT_LEN == 64) {
        // 64 + 512 + 512 = 1088
        component hDash512 = ShaHashBits(64 + SALT_LEN_BITS + HASH_LEN * 8, 512);

        for (var i = 0; i < 1088; i++) {
            hDash512.in[i] <== mDash[i];
        }

        hDash512.out === hash;
    }
}
