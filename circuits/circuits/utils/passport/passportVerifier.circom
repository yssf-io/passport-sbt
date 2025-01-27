pragma circom 2.1.9;

include "@openpassport/zk-email-circuits/utils/array.circom";
include "@openpassport/zk-email-circuits/utils/bytes.circom";
include "../crypto/bitify/bytes.circom";
include "../crypto/hasher/shaBytes/shaBytesDynamic.circom";
include "../crypto/hasher/hash.circom";
include "./signatureAlgorithm.circom";
include "./signatureVerifier.circom";

/// @title PassportVerifier
/// @notice verifies the integrity and the signature of the passport data
/// @param DG_HASH_ALGO Hash algorithm used for DG hashing
/// @param ECONTENT_HASH_ALGO Hash algorithm used for eContent
/// @param signatureAlgorithm Algorithm used for passport signature verification - contains the information about the final hash algorithm
/// @param n Number of bits per chunk the key is split into.
/// @param k Number of chunks the key is split into.
/// @param MAX_ECONTENT_PADDED_LEN Maximum length of padded eContent
/// @param MAX_SIGNED_ATTR_PADDED_LEN Maximum length of padded signed attributes
/// @input dg1 Document Group 1 data (93 bytes)
/// @input dg1_hash_offset Offset for DG1 hash
/// @input eContent eContent data - contains all DG hashes
/// @input eContent_padded_length Padded length of eContent
/// @input signed_attr Signed attributes
/// @input signed_attr_padded_length Padded length of signed attributes
/// @input signed_attr_econtent_hash_offset Offset for eContent hash in signed attributes
/// @input pubKey Public key for signature verification
/// @input signature Passport signature
/// @output eContentShaBytes Hash of eContent
/// @output signedAttrShaBytes Hash of signed attributes

template PassportVerifier(DG_HASH_ALGO, ECONTENT_HASH_ALGO, signatureAlgorithm, n, k, MAX_ECONTENT_PADDED_LEN, MAX_SIGNED_ATTR_PADDED_LEN) {
    assert(MAX_ECONTENT_PADDED_LEN % 64 == 0);

    var kLengthFactor = getKLengthFactor(signatureAlgorithm);
    var kScaled = k * kLengthFactor;

    var DG_HASH_ALGO_BYTES = DG_HASH_ALGO / 8;
    var ECONTENT_HASH_ALGO_BYTES = ECONTENT_HASH_ALGO / 8;
    var SIGNED_ATTR_HASH_ALGO = getHashLength(signatureAlgorithm);
    var SIGNED_ATTR_HASH_ALGO_BYTES = SIGNED_ATTR_HASH_ALGO / 8;

    signal input dg1[93];
    signal input dg1_hash_offset;
    signal input eContent[MAX_ECONTENT_PADDED_LEN];
    signal input eContent_padded_length;
    signal input signed_attr[MAX_SIGNED_ATTR_PADDED_LEN];
    signal input signed_attr_padded_length;
    signal input signed_attr_econtent_hash_offset;
    signal input pubKey_dsc[kScaled];
    signal input signature_passport[kScaled];

    // check offsets refer to valid ranges
    signal dg1OffsetInRange <== LessEqThan(12)([dg1_hash_offset + DG_HASH_ALGO_BYTES, eContent_padded_length]); 
    dg1OffsetInRange === 1;

    signal signedAttrOffsetInRange <== LessEqThan(12)([signed_attr_econtent_hash_offset + ECONTENT_HASH_ALGO_BYTES, signed_attr_padded_length]); 
    signedAttrOffsetInRange === 1;

    // compute hash of DG1
    signal dg1Bits[93 * 8] <== BytesToBitsArray(93)(dg1);
    signal dg1ShaBits[DG_HASH_ALGO] <== ShaHashBits(93 * 8, DG_HASH_ALGO)(dg1Bits);
    signal dg1ShaBytes[DG_HASH_ALGO_BYTES] <== BitsToBytesArray(DG_HASH_ALGO)(dg1ShaBits);

    // assert DG1 hash matches the one in eContent
    signal dg1Hash[DG_HASH_ALGO_BYTES] <== VarShiftLeft(MAX_ECONTENT_PADDED_LEN, DG_HASH_ALGO_BYTES)(eContent, dg1_hash_offset);
    for(var i = 0; i < DG_HASH_ALGO_BYTES; i++) {
        dg1Hash[i] === dg1ShaBytes[i];
    }

    // compute hash of eContent
    signal eContentShaBits[ECONTENT_HASH_ALGO] <== ShaBytesDynamic(ECONTENT_HASH_ALGO, MAX_ECONTENT_PADDED_LEN)(eContent, eContent_padded_length);
    signal output eContentShaBytes[ECONTENT_HASH_ALGO_BYTES] <== BitsToBytesArray(ECONTENT_HASH_ALGO)(eContentShaBits);

    // assert eContent hash matches the one in signedAttr
    signal eContentHashInSignedAttr[ECONTENT_HASH_ALGO_BYTES] <== VarShiftLeft(MAX_SIGNED_ATTR_PADDED_LEN, ECONTENT_HASH_ALGO_BYTES)(signed_attr, signed_attr_econtent_hash_offset);
    for(var i = 0; i < ECONTENT_HASH_ALGO_BYTES; i++) {
        eContentHashInSignedAttr[i] === eContentShaBytes[i];
    }

    // compute hash of signedAttr
    signal signedAttrShaBits[SIGNED_ATTR_HASH_ALGO] <== ShaBytesDynamic(SIGNED_ATTR_HASH_ALGO, MAX_SIGNED_ATTR_PADDED_LEN)(signed_attr, signed_attr_padded_length);
    signal output signedAttrShaBytes[SIGNED_ATTR_HASH_ALGO_BYTES] <== BitsToBytesArray(SIGNED_ATTR_HASH_ALGO)(signedAttrShaBits);

    // verify passport signature
    SignatureVerifier(signatureAlgorithm, n, k)(signedAttrShaBits, pubKey_dsc, signature_passport);
}

