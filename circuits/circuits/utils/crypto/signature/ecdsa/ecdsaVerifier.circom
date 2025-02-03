pragma circom 2.1.9;

include "../../../passport/signatureAlgorithm.circom";
include "ecdsa.circom";

/// @title EcdsaVerifier
/// @notice Verifies an ECDSA signature for a given signature algorithm, public key, and message hash
/// @param signatureAlgorithm The hashing/signature algorithm as defined in `signatureAlgorithm.circom`
/// @param n The number of chunks used to represent integers (e.g., public key components and signature)
/// @param k The base chunk size, scaled based on the signature algorithm
/// @input signature The [R, S] component in an array
/// @input pubKey The public key to verify the signature
/// @input hashParsed The hash of the message to be verified
template EcdsaVerifier(signatureAlgorithm, n, k) {
    var kLengthFactor = getKLengthFactor(signatureAlgorithm);
    var kScaled = k * kLengthFactor;

    var HASH_LEN_BITS = getHashLength(signatureAlgorithm);

    signal input signature[kScaled];
    signal input pubKey[kScaled];
    signal input hashParsed[HASH_LEN_BITS];

    signal hash[n * k];

    //if hash is greater than or equal to the field bits then truncate the rightmost part 
    if (HASH_LEN_BITS >= n * k) { 
        for (var i = 0; i < n * k; i++) {
            hash[i] <== hashParsed[i];
        }
    }
    //if hash is less than the field size then pad zeroes to the left
    if (HASH_LEN_BITS < n * k) {
        for (var i = n * k - 1; i >= 0; i--) {
            if (i <= n * k - 1 - HASH_LEN_BITS) {
                hash[i] <== 0;
            } else { 
                hash[i] <== hashParsed[i - n * k + HASH_LEN_BITS];
            }
        }
    }

    signal signature_r[k]; // ECDSA signature component r
    signal signature_s[k]; // ECDSA signature component s
    signal pubKey_x[k];
    signal pubKey_y[k];

    for (var i = 0; i < k; i++) {
        signature_r[i] <== signature[i];
        signature_s[i] <== signature[i + k];
        pubKey_x[i] <== pubKey[i];
        pubKey_y[i] <== pubKey[i + k];
    }
    signal pubkey_xy[2][k] <== [pubKey_x, pubKey_y];

    var a[k] = get_a(signatureAlgorithm);
    var b[k] = get_b(signatureAlgorithm);
    var p[k] = get_p(signatureAlgorithm);

    // verify eContentHash signature
    component ecdsa_verify = verifyECDSABits(n, k, a, b, p, n * k);

    ecdsa_verify.pubkey <== pubkey_xy;
    ecdsa_verify.signature <== [signature_r, signature_s];
    ecdsa_verify.hashed <== hash;
}

function get_a(signatureAlgorithm) {
    if (signatureAlgorithm == 7 || signatureAlgorithm == 8) {  //secp256r1
        return [ 
            18446744073709551612, 
            4294967295, 
            0, 
            18446744069414584321 
        ];
    }
    if (signatureAlgorithm == 9 || signatureAlgorithm == 23) { //secp384r1
        return [
            4294967292,
            18446744069414584320,
            18446744073709551614,
            18446744073709551615,
            18446744073709551615,
            18446744073709551615
        ];
    }
     if (signatureAlgorithm == 21 || signatureAlgorithm == 24 || signatureAlgorithm == 25 || signatureAlgorithm == 36) { //brainpoolP256r1
        return [
            16810331318623712729,
            18122579188607900780,
            17219079075415130087,
            9032542404991529047
        ];
     }
    if (signatureAlgorithm == 22 || signatureAlgorithm == 26 || signatureAlgorithm == 37) { // brainpoolP384r1
        return [
            335737924824737830,
            9990533504564909291,
            1410020238645393679,
            14032832221039175559,
            4355552632119865248,
            8918115475071440140
        ];
    }

    if (signatureAlgorithm == 27 || signatureAlgorithm == 28 || signatureAlgorithm == 30) { // brainpoolP224r1 
        return [
            3402800963,
            2953063001,
            1310206680,
            3243445073,
            697828262,
            2848877596,
            1755702828
        ];
    }

    if (signatureAlgorithm == 29 || signatureAlgorithm == 38) { // brainpoolP512r1
        return  [
            16699818341992010954,
            9156125524185237433,
            733789637240866997,
            3309403945136634529,
            12120384836935902140,
            10721906936585459216,
            16299214545461923013,
            8660601516620528521
        ];
    }

    if (signatureAlgorithm == 41) { 
        return [
            73786976294838206460,
            73786976294838206463,
            73786976294838206463,
            73786976294838206463,
            73786976294838206463,
            73786976294838206463,
            73786976294838206463,
            576460752303423487
        ];
    }

    return [0];
}

function get_b(signatureAlgorithm) { 
    if (signatureAlgorithm == 7 || signatureAlgorithm == 8) { //secp256r1
        return [
            4309448131093880907,
            7285987128567378166,
            12964664127075681980,
            6540974713487397863
        ];
    }
    if (signatureAlgorithm == 9 || signatureAlgorithm == 23) {
        return [
            3064076045283764975,
            14291673747578343837,
            221811693264799578,
            1737717031765098770,
            10992729701402291481,
            12912154004749740004
        ];
    }
     if (signatureAlgorithm == 21 || signatureAlgorithm == 24 || signatureAlgorithm == 25 || signatureAlgorithm == 36) { //brainpoolP256r1
        return  [
            7767825457231955894,
            10773760575486288334,
            17523706096862592191,
            2800214691157789508
        ];
     }
    if (signatureAlgorithm == 22 || signatureAlgorithm == 26 || signatureAlgorithm == 37) { //brainpoolP384r1
        return [
            4230998357940653073,
            8985869839777909140,
            3352946025465340629,
            3438355245973688998,
            10032249017711215740,
            335737924824737830
        ];
    }

    if (signatureAlgorithm == 27 || signatureAlgorithm == 28 || signatureAlgorithm == 30) { // brainpoolP224r1
        return  [
            946618379,
            1725674354,
            1042363858,
            2837670371,
            2265387953,
            3487842616,
            629208636
        ];
    }

    if (signatureAlgorithm == 29 || signatureAlgorithm == 38) { // brainpoolP512r1
        return [
            2885045271355914019,
            10970857440773072349,
            8645948983640342119,
            3166813089265986637,
            10059573399531886503,
            12116154835845181897,
            16904370861210688858,
            4465624766311842250
        ];
    }

    if (signatureAlgorithm == 41) { 
        return [
            35687965819361312512,
            33244719099633405244,
            68122903767798193136,
            64948772962036742733,
            36008729323586384137,
            4298886627987975365,
            30118149759215298644,
            91854278977009778
        ];
    }

    return [0];
}

function get_p(signatureAlgorithm) { 
    if (signatureAlgorithm == 7 || signatureAlgorithm == 8) { //secp256r1
        return [ 
            18446744073709551615, 
            4294967295, 
            0, 
            18446744069414584321 
        ];
    }
    if (signatureAlgorithm == 9 || signatureAlgorithm == 23) { //secp384r1
        return [
            4294967295,
            18446744069414584320,
            18446744073709551614,
            18446744073709551615,
            18446744073709551615,
            18446744073709551615
        ];
    }
     if (signatureAlgorithm == 21 || signatureAlgorithm == 24 || signatureAlgorithm == 25 || signatureAlgorithm == 36) { //brainpoolP256r1
        return  [
            2311270323689771895,
            7943213001558335528,
            4496292894210231666,
            12248480212390422972
        ];
     }
    if (signatureAlgorithm == 22 || signatureAlgorithm == 26 || signatureAlgorithm == 37) { //brainpoolP384r1
        return [
            9747760000893709395,
            12453481191562877553,
            1347097566612230435,
            1526563086152259252,
            1107163671716839903,
            10140169582434348328
        ];
    }

    if (signatureAlgorithm == 27 || signatureAlgorithm == 28 || signatureAlgorithm == 30) { //brainpoolP224r1
        return [
            2127085823,
            2547681781,
            2963212119,
            1976686471,
            706228261,
            641951366,
            3619763370
        ];
    }

    if (signatureAlgorithm == 29 || signatureAlgorithm == 38) { //brainpoolP512r1
        return [
            2930260431521597683,
            2918894611604883077,
            12595900938455318758,
            9029043254863489090,
            15448363540090652785,
            14641358191536493070,
            4599554755319692295,
            12312170373589877899
        ];
    }

    if (signatureAlgorithm == 41) { 
        return [
            73786976294838206463,
            73786976294838206463,
            73786976294838206463,
            73786976294838206463,
            73786976294838206463,
            73786976294838206463,
            73786976294838206463,
            576460752303423487
        ];
    }

    return [0];
}