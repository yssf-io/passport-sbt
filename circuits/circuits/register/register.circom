pragma circom 2.1.9;

include "../utils/passport/customHashers.circom";
include "../utils/passport/signatureAlgorithm.circom";
include "../utils/passport/date/isValid.circom";
include "circomlib/circuits/poseidon.circom";
include "../utils/passport/passportVerifier.circom";
include "../utils/passport/constants.circom";
include "../utils/crypto/bitify/splitWordsToBytes.circom";
include "../utils/crypto/bitify/bytes.circom";

/// @title REGISTER
/// @notice Main circuit — verifies the integrity of the passport data, the signature, and generates commitment and nullifier
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
/// @input pubKey_csca_hash CSCA public key hash
/// @input secret Secret for commitment generation. Saved by the user to access this commitment
/// @input salt One time secret to generate the glue
/// @output nullifier Generated nullifier -  deterministic on the passport data
/// @output commitment Commitment that will be added to the onchain registration tree
/// @output glue Used to link register and dsc proofs - the same is generated in the dsc circuit

template REGISTER(
    DG_HASH_ALGO,
    ECONTENT_HASH_ALGO,
    signatureAlgorithm,
    n,
    k,
    MAX_ECONTENT_PADDED_LEN,
    MAX_SIGNED_ATTR_PADDED_LEN
) {
    var kLengthFactor = getKLengthFactor(signatureAlgorithm);
    var kScaled = k * kLengthFactor;
    var HASH_LEN_BITS = getHashLength(signatureAlgorithm);
    var HASH_LEN_BYTES = HASH_LEN_BITS / 8;

    var ECONTENT_HASH_ALGO_BYTES = ECONTENT_HASH_ALGO / 8;

    var maxDscPubkeyBytesLength = getMaxDscPubKeyLength();
    var dsc_pubkey_length_bytes = (getKeyLength(signatureAlgorithm) / 8) * kLengthFactor;

    // signal input raw_dsc[MAX_DSC_LENGTH];
    // signal input raw_dsc_actual_length;

    // signal input dsc_pubKey_bytes[maxPubkeyBytesLength];
    // signal input dsc_pubKey_offset;
    // signal input dsc_pubkey_length_bytes;

    signal input dg1[93];
    signal input dg1_hash_offset;
    signal input eContent[MAX_ECONTENT_PADDED_LEN];
    signal input eContent_padded_length;
    signal input signed_attr[MAX_SIGNED_ATTR_PADDED_LEN];
    signal input signed_attr_padded_length;
    signal input signed_attr_econtent_hash_offset;
    signal input pubKey_dsc[kScaled];
    signal input signature_passport[kScaled];

    signal input pubKey_csca_hash;
    
    signal input secret;
    signal input salt;


    // This means the attestation is a passport
    signal attestation_id <== 1;

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

    signal dg1_packed_hash <== PackBytesAndPoseidon(93)(dg1);
    signal eContent_shaBytes_packed_hash <== PackBytesAndPoseidon(ECONTENT_HASH_ALGO_BYTES)(passportVerifier.eContentShaBytes);

    signal pubKey_dsc_hash_commitement <== CustomHasher(kScaled)(pubKey_dsc);
        
    //convert DSC public key to 35 words of 120 bits each
    // component standardizedDSCPubKey = StandardizeDSCPubKey(n, k, kLengthFactor);
    // standardizedDSCPubKey.pubKey_dsc <== pubKey_dsc;

    // signal pubKey_dsc_hash <== CustomHasher(35)(standardizedDSCPubKey.out);
    
    // signal output commitment <== Poseidon(6)([
    //     secret,
    //     attestation_id,
    //     dg1_packed_hash,
    //     eContent_shaBytes_packed_hash,
    //     pubKey_dsc_hash_commitement,
    //     pubKey_csca_hash
    // ]);
    
    // signal output glue <== Poseidon(4)([salt, dsc_pubkey_length_bytes, pubKey_dsc_hash, pubKey_csca_hash]);
}