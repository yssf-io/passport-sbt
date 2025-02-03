pragma circom 2.1.9;

include "circomlib/circuits/bitify.circom";
include "../utils/crypto/hasher/shaBytes/shaBytesDynamic.circom";
include "circomlib/circuits/comparators.circom";
include "../utils/crypto/hasher/hash.circom";
include "circomlib/circuits/poseidon.circom";
include "@zk-kit/binary-merkle-root.circom/src/binary-merkle-root.circom";
include "../utils/passport/customHashers.circom";
include "../utils/passport/signatureAlgorithm.circom";
include "../utils/passport/signatureVerifier.circom";
include "../utils/passport/checkPubkeysEqual.circom";
include "../utils/passport/constants.circom";
include "../utils/crypto/bitify/bytes.circom";
include "../utils/passport/BytesToNum.circom";

/// @title DSC
/// @notice Circuit for verifying DSC certificate signature using CSCA certificate
/// @param signatureAlgorithm Algorithm used for DSC signature verification - contains the information about the final hash algorithm
/// @param n_csca Number of bits per chunk the CSCA key is split into
/// @param k_csca Number of chunks the CSCA key is split into
/// @input raw_csca Raw CSCA certificate data
/// @input raw_csca_actual_length Actual length of CSCA certificate
/// @input csca_pubKey_offset Offset of CSCA public key in certificate
/// @input csca_pubKey_actual_size Actual size of CSCA public key in bytes
/// @input raw_dsc Raw DSC certificate data
/// @input raw_dsc_padded_length Actual length of DSC certificate
/// @input csca_pubKey CSCA public key for signature verification
/// @input signature DSC signature
/// @input merkle_root Root of CSCA Merkle tree
/// @input path Path indices for CSCA Merkle proof
/// @input siblings Sibling hashes for CSCA Merkle proof
/// @output dsc_tree_leaf Leaf to be added to the DSC Merkle tree
template DSC(
    signatureAlgorithm,
    n_csca,
    k_csca
) {
    var MAX_CSCA_LENGTH = getMaxCSCALength();
    var MAX_DSC_LENGTH = getMaxDSCLength();
    var nLevels = getMaxCSCALevels();

    // variables verification
    assert(MAX_CSCA_LENGTH % 64 == 0);
    assert(MAX_DSC_LENGTH % 64 == 0);
    // assert(n_csca * k_csca > max_dsc_bytes); // not sure what this is for
    assert(n_csca <= (255 \ 2));

    var minKeyLength = getMinKeyLength(signatureAlgorithm);
    var kLengthFactor = getKLengthFactor(signatureAlgorithm);
    var kScaled = k_csca * kLengthFactor;
    var hashLength = getHashLength(signatureAlgorithm);

    var MAX_CSCA_PUBKEY_LENGTH = n_csca * kScaled / 8;

    signal input raw_csca[MAX_CSCA_LENGTH];
    signal input raw_csca_actual_length;
    signal input csca_pubKey_offset;
    signal input csca_pubKey_actual_size;

    signal input raw_dsc[MAX_DSC_LENGTH];
    signal input raw_dsc_padded_length;

    signal input csca_pubKey[kScaled];
    signal input signature[kScaled];

    signal input merkle_root;
    signal input path[nLevels];
    signal input siblings[nLevels];

    // first, compute raw_dsc_actual_length
    // by getting the values of the last 4 bytes of the padded length
    // cf sha padding
    signal last_four_bytes_of_padded_length[4] <== SelectSubArray(MAX_DSC_LENGTH, 4)(raw_dsc, raw_dsc_padded_length - 4, 4);
    signal computed_length_bits <== BytesToNum()(last_four_bytes_of_padded_length);
    signal raw_dsc_actual_length <== computed_length_bits / 8;

    // sanity check: raw_dsc[raw_dsc_actual_length] should be 128
    signal raw_dsc_at_actual_length <== ItemAtIndex(MAX_DSC_LENGTH)(raw_dsc, raw_dsc_actual_length);
    signal isByte128 <== IsEqual()([raw_dsc_at_actual_length, 128]);
    isByte128 === 1;

    // check that raw_dsc is padded with 0s after the sha padding
    // this should guarantee the dsc commitment is unique for each commitment
    component byte_checks[MAX_DSC_LENGTH];
    for (var i = 0; i < MAX_DSC_LENGTH; i++) {
        byte_checks[i] = GreaterThan(12);
        byte_checks[i].in[0] <== i;
        byte_checks[i].in[1] <== raw_dsc_padded_length;
        
        // If i >= raw_dsc_padded_length, the byte must be 0
        raw_dsc[i] * byte_checks[i].out === 0;
    }
    
    // check csca_pubKey_actual_size is at least the minimum key length
    signal csca_pubKey_actual_size_in_range <== GreaterEqThan(12)([
        csca_pubKey_actual_size,
        minKeyLength * kLengthFactor / 8
    ]);
    csca_pubKey_actual_size_in_range === 1;

    // check offsets refer to valid ranges
    signal csca_pubKey_offset_in_range <== LessEqThan(12)([
        csca_pubKey_offset + csca_pubKey_actual_size,
        raw_csca_actual_length
    ]); 
    csca_pubKey_offset_in_range === 1;

    // compute leaf in the CSCA Merkle tree and verify inclusion
    signal csca_hash <== PackBytesAndPoseidon(MAX_CSCA_LENGTH)(raw_csca);
    signal csca_tree_leaf <== Poseidon(2)([csca_hash, raw_csca_actual_length]);
    signal computed_merkle_root <== BinaryMerkleRoot(nLevels)(csca_tree_leaf, nLevels, path, siblings);
    merkle_root === computed_merkle_root;

    // get CSCA public key from the certificate
    signal extracted_csca_pubKey[MAX_CSCA_PUBKEY_LENGTH] <== SelectSubArray(MAX_CSCA_LENGTH, MAX_CSCA_PUBKEY_LENGTH)(
        raw_csca,
        csca_pubKey_offset,
        csca_pubKey_actual_size
    );

    // check if the CSCA public key is the same as the one in the certificate
    // If we end up adding the pubkey in the CSCA leaf, we'll be able to remove this check
    CheckPubkeysEqual(n_csca, kScaled, kLengthFactor, MAX_CSCA_PUBKEY_LENGTH)(
        csca_pubKey,
        extracted_csca_pubKey,
        csca_pubKey_actual_size
    );

    // verify DSC signature
    // raw_dsc_padded_length is constrained because an incorrect one
    // would yield hashes that have not been signed
    signal hashedCertificate[hashLength] <== ShaBytesDynamic(hashLength, MAX_DSC_LENGTH)(raw_dsc, raw_dsc_padded_length);
    SignatureVerifier(signatureAlgorithm, n_csca, k_csca)(hashedCertificate, csca_pubKey, signature);
    
    // generate DSC leaf as poseidon(dsc_hash_with_actual_length, csca_tree_leaf)
    signal dsc_hash <== PackBytesAndPoseidon(MAX_DSC_LENGTH)(raw_dsc);
    signal dsc_hash_with_actual_length <== Poseidon(2)([dsc_hash, raw_dsc_actual_length]);
    signal output dsc_tree_leaf <== Poseidon(2)([dsc_hash_with_actual_length, csca_tree_leaf]);
}