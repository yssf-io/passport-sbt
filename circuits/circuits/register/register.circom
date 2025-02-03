pragma circom 2.1.9;

include "../utils/passport/customHashers.circom";
include "../utils/passport/signatureAlgorithm.circom";
include "../utils/passport/date/isValid.circom";
include "circomlib/circuits/poseidon.circom";
include "../utils/passport/passportVerifier.circom";
include "../utils/passport/constants.circom";
include "../utils/crypto/bitify/splitWordsToBytes.circom";
include "../utils/crypto/bitify/bytes.circom";
include "@zk-kit/binary-merkle-root.circom/src/binary-merkle-root.circom";
include "../utils/passport/checkPubkeysEqual.circom";

/// @title REGISTER
/// @notice Main circuit — verifies the integrity of the passport data, the signature, and generates commitment and nullifier
/// @param DG_HASH_ALGO Hash algorithm used for DG hashing
/// @param ECONTENT_HASH_ALGO Hash algorithm used for eContent
/// @param signatureAlgorithm Algorithm used for passport signature verification - contains the information about the final hash algorithm
/// @param n Number of bits per chunk the key is split into.
/// @param k Number of chunks the key is split into.
/// @param MAX_ECONTENT_PADDED_LEN Maximum length of padded eContent
/// @param MAX_SIGNED_ATTR_PADDED_LEN Maximum length of padded signed attributes
/// @input raw_dsc Raw DSC certificate data
/// @input raw_dsc_actual_length Actual length of DSC certificate
/// @input dsc_pubKey_offset Offset of DSC public key in certificate
/// @input dsc_pubKey_actual_size Actual size of DSC public key
/// @input dg1 Document Group 1 data (93 bytes)
/// @input dg1_hash_offset Offset for DG1 hash
/// @input eContent eContent data - contains all DG hashes
/// @input eContent_padded_length Padded length of eContent
/// @input signed_attr Signed attributes
/// @input signed_attr_padded_length Padded length of signed attributes
/// @input signed_attr_econtent_hash_offset Offset for eContent hash in signed attributes
/// @input pubKey_dsc DSC public key for signature verification
/// @input signature_passport Passport signature
/// @input merkle_root Root of DSC Merkle tree
/// @input leaf_depth Actual size of the merkle tree
/// @input path Path indices for DSC Merkle proof
/// @input siblings Sibling hashes for DSC Merkle proof
/// @input csca_tree_leaf Leaf of CSCA Merkle tree
/// @input secret Secret for commitment generation. Saved by the user to access their commitment
/// @output nullifier Generated nullifier - deterministic on the passport data
/// @output commitment Commitment that will be added to the onchain registration tree
template REGISTER(
    DG_HASH_ALGO,
    ECONTENT_HASH_ALGO,
    signatureAlgorithm,
    n,
    k,
    MAX_ECONTENT_PADDED_LEN,
    MAX_SIGNED_ATTR_PADDED_LEN
) {
    var MAX_DSC_LENGTH = getMaxDSCLength();
    var nLevels = getMaxDSCLevels();

    assert(MAX_DSC_LENGTH % 64 == 0);
    
    // This means the attestation is a passport
    var attestation_id = 1;

    var minKeyLength = getMinKeyLength(signatureAlgorithm);
    var kLengthFactor = getKLengthFactor(signatureAlgorithm);
    var kScaled = k * kLengthFactor;

    var HASH_LEN_BITS = getHashLength(signatureAlgorithm);
    var HASH_LEN_BYTES = HASH_LEN_BITS / 8;
    var ECONTENT_HASH_ALGO_BYTES = ECONTENT_HASH_ALGO / 8;

    var MAX_DSC_PUBKEY_LENGTH = n * kScaled / 8;

    signal input raw_dsc[MAX_DSC_LENGTH];
    signal input raw_dsc_actual_length;
    signal input dsc_pubKey_offset;
    signal input dsc_pubKey_actual_size;

    signal input dg1[93];
    signal input dg1_hash_offset;
    signal input eContent[MAX_ECONTENT_PADDED_LEN];
    signal input eContent_padded_length;
    signal input signed_attr[MAX_SIGNED_ATTR_PADDED_LEN];
    signal input signed_attr_padded_length;
    signal input signed_attr_econtent_hash_offset;
    signal input pubKey_dsc[kScaled];
    signal input signature_passport[kScaled];

    signal input merkle_root;
    signal input leaf_depth;
    signal input path[nLevels];
    signal input siblings[nLevels];

    signal input csca_tree_leaf;
    
    signal input secret;

    // check dsc_pubKey_actual_size is at least the minimum key length
    signal dsc_pubKey_actual_size_in_range <== GreaterEqThan(12)([
        dsc_pubKey_actual_size,
        minKeyLength * kLengthFactor / 8
    ]);
    dsc_pubKey_actual_size_in_range === 1;

    // check offsets refer to valid ranges
    signal dsc_pubKey_offset_in_range <== LessEqThan(12)([
        dsc_pubKey_offset + dsc_pubKey_actual_size,
        raw_dsc_actual_length
    ]); 
    dsc_pubKey_offset_in_range === 1;

    // generate DSC leaf as poseidon(dsc_hash, csca_tree_leaf)
    signal dsc_hash <== PackBytesAndPoseidon(MAX_DSC_LENGTH)(raw_dsc);
    signal dsc_hash_with_actual_length <== Poseidon(2)([dsc_hash, raw_dsc_actual_length]);
    signal dsc_tree_leaf <== Poseidon(2)([dsc_hash_with_actual_length, csca_tree_leaf]);
    signal computed_merkle_root <== BinaryMerkleRoot(nLevels)(dsc_tree_leaf, leaf_depth, path, siblings);
    merkle_root === computed_merkle_root;

    // get DSC public key from the certificate
    signal extracted_dsc_pubKey[MAX_DSC_PUBKEY_LENGTH] <== SelectSubArray(MAX_DSC_LENGTH, MAX_DSC_PUBKEY_LENGTH)(
        raw_dsc,
        dsc_pubKey_offset,
        dsc_pubKey_actual_size
    );

    // check if the DSC public key is the same as the one in the certificate
    CheckPubkeysEqual(n, kScaled, kLengthFactor, MAX_DSC_PUBKEY_LENGTH)(
        pubKey_dsc,
        extracted_dsc_pubKey,
        dsc_pubKey_actual_size
    );

    // verify passport signature
    component passportVerifier = PassportVerifier(
        DG_HASH_ALGO,
        ECONTENT_HASH_ALGO,
        signatureAlgorithm,
        n,
        k,
        MAX_ECONTENT_PADDED_LEN,
        MAX_SIGNED_ATTR_PADDED_LEN
    );

    passportVerifier.dg1 <== dg1;
    passportVerifier.dg1_hash_offset <== dg1_hash_offset;
    passportVerifier.eContent <== eContent;
    passportVerifier.eContent_padded_length <== eContent_padded_length;
    passportVerifier.signed_attr <== signed_attr;
    passportVerifier.signed_attr_padded_length <== signed_attr_padded_length;
    passportVerifier.signed_attr_econtent_hash_offset <== signed_attr_econtent_hash_offset;
    passportVerifier.pubKey_dsc <== pubKey_dsc;
    passportVerifier.signature_passport <== signature_passport;

    signal output nullifier <== PackBytesAndPoseidon(HASH_LEN_BYTES)(passportVerifier.signedAttrShaBytes);

    // generate commitment
    signal dg1_packed_hash <== PackBytesAndPoseidon(93)(dg1);
    signal eContent_shaBytes_packed_hash <== PackBytesAndPoseidon(ECONTENT_HASH_ALGO_BYTES)(passportVerifier.eContentShaBytes);
    
    signal output commitment <== Poseidon(5)([
        secret,
        attestation_id,
        dg1_packed_hash,
        eContent_shaBytes_packed_hash,
        dsc_tree_leaf
    ]);
}