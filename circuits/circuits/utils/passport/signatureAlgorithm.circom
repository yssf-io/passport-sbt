pragma circom 2.1.9;

/***

ID to Signature Algorithm
  1: rsa_sha256_65537_2048
  3: rsa_sha1_65537_2048
  4: rsapss_sha256_65537_2048
  7: ecdsa_sha1_secp256r1_256
  8: ecdsa_sha256_secp256r1_256
  9: ecdsa_sha384_secp384r1_384
 10: rsa_sha256_65537_4096
 11: rsa_sha1_65537_4096
 12: rsapss_sha256_65537_4096
 13: rsa_sha256_3_2048
 14: rsa_sha256_65537_3072
 15: rsa_sha512_65537_4096
 16: rsapss_sha256_3_3072
 17: rsapss_sha256_3_4096
 18: rsapss_sha384_65537_3072
 19: rsapss_sha256_65537_3072
 21: ecdsa_sha256_brainpoolP256r1_256
 22: ecdsa_sha384_brainpoolP384r1_384
 23: ecdsa_sha256_secp384r1_384
 24: ecdsa_sha384_brainpoolP256r1_256
 25: ecdsa_sha512_brainpoolP256r1_256
 26: ecdsa_sha512_brainpoolP384r1_384
 27: ecdsa_sha1_brainpoolP224r1_224
 28: ecdsa_sha256_brainpoolP224r1_224
 29: ecdsa_sha512_brainpoolP512r1_512
 30: ecdsa_sha224_brainpoolP224r1_224
 31: rsa_sha512_65537_2048
 32: rsa_sha256_3_4096
 33: rsa_sha1_3_4096
 34: rsa_sha384_65537_4096
 35: rsapss_sha384_65537_4096
 36: ecdsa_sha1_brainpoolP256r1_256
 37: ecdsa_sha256_brainpoolP384r1_384
 38: ecdsa_sha384_brainpoolP512r1_512
 39: rsapss_sha512_65537_4096
 40: ecdsa_sha256_secp521r1_256
 41: ecdsa_sha512_secp521r1_521
 42: rsapss_sha512_65537_2048
 43: rsapss_sha256_3_2048
 44: ecdsa_sha224_secp224r1_224
*/


/// @title GetHashLength
/// @notice Returns the length of the hash in bits for a given signature algorithm
/// @param signatureAlgorithm ID of the signature algorithm
/// @output hashLength Length of the hash in bits
function getHashLength(signatureAlgorithm) {
    if (signatureAlgorithm == 1 ) {
        return 256;
    }
    if (signatureAlgorithm == 3) {
        return 160;
    }
    if (signatureAlgorithm == 4) {
        return 256;
    }
    if (signatureAlgorithm == 7) {
        return 160;
    }
    if (signatureAlgorithm == 8) {
        return 256;
    }
    if (signatureAlgorithm == 9) {
        return 384;
    }
    if (signatureAlgorithm == 10) {
        return 256;
    }
    if (signatureAlgorithm == 11) {
        return 160;
    }
    if (signatureAlgorithm == 12) {
        return 256;
    }
    if (signatureAlgorithm == 13) {
        return 256;
    }
    if (signatureAlgorithm == 14) {
        return 256;
    }
    if (signatureAlgorithm == 15) {
        return 512;
    }
    if (signatureAlgorithm == 16) {
        return 256;
    }
    if (signatureAlgorithm == 17) {
        return 256;
    }
    if (signatureAlgorithm == 18) {
        return 384;
    }
    if (signatureAlgorithm == 19) {
        return 256;
    }
    if (signatureAlgorithm == 20) {
        return 256;
    }
    if (signatureAlgorithm == 21) { 
        return 256;
    }
    if (signatureAlgorithm == 22) {
        return 384;
    }
    if (signatureAlgorithm == 23) { 
        return 256;
    }
    if (signatureAlgorithm == 24) {
        return 384;
    }
    if (signatureAlgorithm == 25) {
        return 512; 
    }
    if (signatureAlgorithm == 26) { 
        return 512;
    }
    if (signatureAlgorithm == 27) { 
        return 160;
    }
    if (signatureAlgorithm == 28) { 
        return 256;
    }
    if (signatureAlgorithm == 29) { 
        return 512;
    }
    if (signatureAlgorithm == 30) { 
        return 224;
    }
    if (signatureAlgorithm == 31) {
        return 512;
    }
    if (signatureAlgorithm == 32) {
        return 256;
    }
    if (signatureAlgorithm == 33) {
        return 160;
    }
    if (signatureAlgorithm == 34) {
        return 384;
    }
    if (signatureAlgorithm == 35) {
        return 384;
    }
    if (signatureAlgorithm == 36) {
        return 160;
    }
    if (signatureAlgorithm == 37) {
        return 256;
    }
    if (signatureAlgorithm == 38) {
        return 384;
    }
    if (signatureAlgorithm == 39) {
        return 512;
    }
    if (signatureAlgorithm == 40) {
        return 256;
    }
    if (signatureAlgorithm == 41) {
        return 512;
    }
    if (signatureAlgorithm == 42) {
        return 512;
    }
    if (signatureAlgorithm == 43) {
        return 256;
    }
    if (signatureAlgorithm == 44) {
        return 224;
    }
    return 0;
}

/// @title GetMinKeyLength
/// @notice Returns the minimum length of the key in bits for a given signature algorithm
/// @param signatureAlgorithm ID of the signature algorithm
/// @output keyLength Minimum length of the key in bits
/// @dev for RSAPSS and ECDSA, it's always the same as in the circuit name
/// @dev for RSA, it can be lower, because we use the same circuit for multiple key lengths
function getMinKeyLength(signatureAlgorithm) {
    if (signatureAlgorithm == 1 ) {
        return 2048;
    }
    if (signatureAlgorithm == 3) {
        return 2048;
    }
    if (signatureAlgorithm == 4) {
        return 2048;
    }
    if (signatureAlgorithm == 7) {
        return 256;
    }
    if (signatureAlgorithm == 8) {
        return 256;
    }
    if (signatureAlgorithm == 9) {
        return 384;
    }
    if (signatureAlgorithm == 10) {
        return 2048; // down to 2048 for 4096
    }
    if (signatureAlgorithm == 11) {
        return 2048; // down to 2048 for 4096
    }
    if (signatureAlgorithm == 12) {
        return 4096;
    }
    if (signatureAlgorithm == 13) {
        return 2048;
    }
    if (signatureAlgorithm == 14) {
        return 2048; // down to 2048 for 3072 (not used now)
    }
    if (signatureAlgorithm == 15) {
        return 2048; // down to 2048 for 4096
    }
    if (signatureAlgorithm == 16) {
        return 3072;
    }
    if (signatureAlgorithm == 17) {
        return 4096;
    }
    if (signatureAlgorithm == 18) {
        return 3072;
    }
    if (signatureAlgorithm == 19) {
        return 3072;
    }
    if (signatureAlgorithm == 21) { 
        return 256;
    }
    if (signatureAlgorithm == 22) { 
        return 384;
    }
    if (signatureAlgorithm == 23) { 
        return 384;
    }
    if (signatureAlgorithm == 24) { 
        return 256;
    } 
    if (signatureAlgorithm == 25) { 
        return 256;
    }
    if (signatureAlgorithm == 26) { 
        return 384;
    }
    if (signatureAlgorithm == 27) { 
        return 224;
    }
    if (signatureAlgorithm == 28) { 
        return 224;
    }
    if (signatureAlgorithm == 29) { 
        return 512;
    }
    if (signatureAlgorithm == 30) { 
        return 224;
    }
    if (signatureAlgorithm == 31) {
        return 2048;
    }
    if (signatureAlgorithm == 32) {
        return 2048; // down to 2048 for 4096
    }
    if (signatureAlgorithm == 33) {
        return 2048; // down to 2048 for 4096
    }
    if (signatureAlgorithm == 34) {
        return 2048; // down to 2048 for 4096
    }
    if (signatureAlgorithm == 35) {
        return 4096;
    }
    if (signatureAlgorithm == 36) {
        return 256;
    }
    if (signatureAlgorithm == 37) {
        return 384;
    }
    if (signatureAlgorithm == 38) {
        return 512;
    }
    if (signatureAlgorithm == 39) {
        return 4096;
    }
    if (signatureAlgorithm == 40) {
        return 521;
    }
    if (signatureAlgorithm == 41) {
        return 521;
    }
    if (signatureAlgorithm == 42) {
        return 2048;
    }
    if (signatureAlgorithm == 43) {
        return 2048;
    }
    if (signatureAlgorithm == 44) {
        return 224;
    }
    return 4096; // default to highest key length
}

/// @title GetKLengthFactor
/// @notice Returns the length factor for the key in bits for a given signature algorithm — 1 for rsa, 2 for ecdsa
/// @param signatureAlgorithm ID of the signature algorithm
/// @output kLengthFactor Length factor for the key in bits
/// @dev needed as ecdsa keys are composed of x and y coordinates, rsa keys are just the modulus (exponent is defined below)
function getKLengthFactor(signatureAlgorithm) {
    if (signatureAlgorithm == 1) {
        return 1;
    }
    if (signatureAlgorithm == 3) {
        return 1;
    }
    if (signatureAlgorithm == 4) {
        return 1;
    }
    if (signatureAlgorithm == 7) {
        return 2;
    }
    if (signatureAlgorithm == 8) {
        return 2;
    }
    if (signatureAlgorithm == 9) {
        return 2;
    }
    if (signatureAlgorithm == 10) {
        return 1;
    }
    if (signatureAlgorithm == 11) {
        return 1;
    }
    if (signatureAlgorithm == 12) {
        return 1;
    }
    if (signatureAlgorithm == 13) {
        return 1;
    }
    if (signatureAlgorithm == 14) {
        return 1;
    }
    if (signatureAlgorithm == 15) {
        return 1;
    }
    if (signatureAlgorithm == 16) {
        return 1;
    }
    if (signatureAlgorithm == 17) {
        return 1;
    }
    if (signatureAlgorithm == 18) {
        return 1;
    }
    if (signatureAlgorithm == 19) {
        return 1;
    }
    if (signatureAlgorithm == 21) { 
        return 2;
    }
    if (signatureAlgorithm == 22) { 
        return 2;
    }
    if (signatureAlgorithm == 23) { 
        return 2;
    }
    if (signatureAlgorithm == 24) { 
        return 2;
    }
    if (signatureAlgorithm == 25) { 
        return 2;
    }
    if (signatureAlgorithm == 26) { 
        return 2;
    }
    if (signatureAlgorithm == 27) { 
        return 2;
    }
    if (signatureAlgorithm == 28) { 
        return 2;
    }
    if (signatureAlgorithm == 29) { 
        return 2;
    }
    if (signatureAlgorithm == 30) { 
        return 2;
    }
    if (signatureAlgorithm == 31) {
        return 1;
    }
    if (signatureAlgorithm == 32) {
        return 1;
    }
    if (signatureAlgorithm == 33) {
        return 1;
    }
    if (signatureAlgorithm == 34) {
        return 1;
    }
    if (signatureAlgorithm == 35) {
        return 1;
    }
    if (signatureAlgorithm == 36) {
        return 2;
    }
    if (signatureAlgorithm == 37) {
        return 2;
    }
    if (signatureAlgorithm == 38) {
        return 2;
    }
    if (signatureAlgorithm == 39) {
        return 1;
    }
    if (signatureAlgorithm == 40) {
        return 2;
    }
    if (signatureAlgorithm == 41) {
        return 2;
    }
    if (signatureAlgorithm == 42) {
        return 1;
    }
    if (signatureAlgorithm == 43) {
        return 1;
    }
    if (signatureAlgorithm == 44) {
        return 2;
    }
    return 0;

}

/// @title GetExponentBits
/// @notice Returns the amounts of bits of the exponent of type 2^n +1
/// @param signatureAlgorithm ID of the signature algorithm
/// @output exponentBits Amount of bits of the exponent
function getExponentBits(signatureAlgorithm) {
    
    if (signatureAlgorithm == 1 ) {
        return 17; // 65537
    }
    if (signatureAlgorithm == 3 ) {
        return 17;
    }
    if (signatureAlgorithm == 4 ) {
        return 17;
    }
    if (signatureAlgorithm == 10) {
        return 17;
    }
    if (signatureAlgorithm == 11) {
        return 17;
    }
    if (signatureAlgorithm == 12) {
        return 17;
    }
    if (signatureAlgorithm == 13) {
        return 2; // 3
    }
    if (signatureAlgorithm == 14) {
        return 17;
    }
    if (signatureAlgorithm == 15) {
        return 17;
    }
    if (signatureAlgorithm == 16) {
        return 2;
    }
    if (signatureAlgorithm == 17) {
        return 2;
    }
    if (signatureAlgorithm == 18) {
        return 17;
    }
    if (signatureAlgorithm == 19) {
        return 17;
    }
    if (signatureAlgorithm == 31) {
        return 17;
    }
    if (signatureAlgorithm == 32) {
        return 2;
    }
    if (signatureAlgorithm == 33) {
        return 2;
    }
    if (signatureAlgorithm == 34) {
        return 17;
    }
    if (signatureAlgorithm == 35) {
        return 17;
    }
    if (signatureAlgorithm == 39) {
        return 17;
    }
    if (signatureAlgorithm == 42) {
        return 17;
    }
    if (signatureAlgorithm == 43) {
        return 2;
    }
    return 0;
}
