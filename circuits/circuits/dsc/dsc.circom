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
// include "../utils/crypto/utils/WordToBytes.circom";
include "../utils/passport/constants.circom";
include "../utils/crypto/bitify/bytes.circom";
// include "../utils/crypto/bitify/splitWordsToBytes.circom";

template DSC(
    signatureAlgorithm,
    n_csca,
    k_csca
) {
    var MAX_CSCA_LENGTH = getMaxCSCALength();
    var MAX_DSC_LENGTH = getMaxDSCLength();
    var MAX_CSCA_PUBKEY_LENGTH = getMaxCSCAPubKeyLength();
    var nLevels = getMaxCSCALevels();

    // variables verification
    assert(MAX_CSCA_LENGTH % 64 == 0); // it's 1664 currently
    assert(MAX_DSC_LENGTH % 64 == 0); // it's 1664 currently
    // assert(n_csca * k_csca > max_dsc_bytes); // not sure what this is for
    assert(n_csca <= (255 \ 2));

    var hashLength = getHashLength(signatureAlgorithm);
    var kLengthFactor = getKLengthFactor(signatureAlgorithm);
    var kScaled = k_csca * kLengthFactor;

    var csca_pubkey_length_bytes = (getKeyLength(signatureAlgorithm) / 8) * kLengthFactor;

    signal input raw_csca[MAX_CSCA_LENGTH];
    signal input raw_csca_actual_length;
    signal input csca_pubKey_offset;

    signal input raw_dsc[MAX_DSC_LENGTH];
    signal input raw_dsc_actual_length;

    signal input csca_pubKey[kScaled];
    signal input signature[kScaled];

    // signal input merkle_root;
    // signal input path[nLevels];
    // signal input siblings[nLevels];

    log("raw_csca_actual_length", raw_csca_actual_length);
    log("csca_pubKey_offset", csca_pubKey_offset);
    log("csca_pubkey_length_bytes", csca_pubkey_length_bytes);

    log("raw_dsc_actual_length", raw_dsc_actual_length);

    // check offsets refer to valid ranges
    signal csca_pubKey_offset_in_range <== LessEqThan(14)([ // TODO update this value with log2(MAX_CSCA_LENGTH)
        csca_pubKey_offset + csca_pubkey_length_bytes,
        raw_csca_actual_length
    ]); 
    csca_pubKey_offset_in_range === 1;

    // compute leaf in the CSCA Merkle tree and verify inclusion
    signal csca_tree_leaf <== PackBytesAndPoseidon(MAX_CSCA_LENGTH)(raw_csca);
    // signal computed_merkle_root <== BinaryMerkleRoot(nLevels)(csca_tree_leaf, nLevels, path, siblings);
    // merkle_root === computed_merkle_root;

    // get CSCA public key from the certificate
    signal extracted_csca_pubKey[MAX_CSCA_PUBKEY_LENGTH] <== SelectSubArray(MAX_CSCA_LENGTH, MAX_CSCA_PUBKEY_LENGTH)(raw_csca, csca_pubKey_offset, csca_pubkey_length_bytes);

    // check if the CSCA public key is the same as the one in the certificate
    // If we end up adding the pubkey in the CSCA leaf, we'll be able to remove this check
    CheckPubkeysEqual(n_csca, kScaled, csca_pubkey_length_bytes, MAX_CSCA_PUBKEY_LENGTH)(csca_pubKey, extracted_csca_pubKey);

    // verify DSC signature
    signal hashedCertificate[hashLength] <== ShaBytesDynamic(hashLength, MAX_DSC_LENGTH)(raw_dsc, raw_dsc_actual_length);
    SignatureVerifier(signatureAlgorithm, n_csca, k_csca)(hashedCertificate, csca_pubKey, signature);
    
    // generate DSC leaf as poseidon(csca_hash, dsc_hash)
    signal dsc_hash <== PackBytesAndPoseidon(MAX_DSC_LENGTH)(raw_dsc);
    signal output dsc_tree_leaf <== Poseidon(2)([csca_tree_leaf, dsc_hash]);
}