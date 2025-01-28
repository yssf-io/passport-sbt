pragma circom 2.1.9;

include "../crypto/bitify/bytes.circom";
include "../crypto/bitify/splitWordsToBytes.circom";

/// @title CheckPubkeysEqual
/// @notice Checks if the CSCA public key given is the same as the one in the certificate
/// @param kScaled Number of chunks the given key is split into.
/// @param MAX_CSCA_PUBKEY_LENGTH Maximum length of the parsed CSCA public key
/// @input csca_pubKey CSCA public key given by the user, formatted for signature verification
/// @input extracted_csca_pubKey CSCA public key extracted from the certificate
template CheckPubkeysEqual(n, kScaled, csca_pubkey_length_bytes, MAX_CSCA_PUBKEY_LENGTH) {
    signal input csca_pubKey[kScaled];
    signal input extracted_csca_pubKey[MAX_CSCA_PUBKEY_LENGTH];

    signal csca_pubKey_bytes[MAX_CSCA_PUBKEY_LENGTH] <== WordsToBytes(n, kScaled, n * kScaled / 8)(csca_pubKey);

    // reverse bytes order
    signal padded_csca_pubKey_bytes[MAX_CSCA_PUBKEY_LENGTH];
    for (var i = 0; i < csca_pubkey_length_bytes; i++) {
        padded_csca_pubKey_bytes[i] <== csca_pubKey_bytes[csca_pubkey_length_bytes - i - 1];
    }

    for (var i = csca_pubkey_length_bytes; i < MAX_CSCA_PUBKEY_LENGTH; i++) {
        padded_csca_pubKey_bytes[i] <== 0;
    }

    for (var i = 0; i < MAX_CSCA_PUBKEY_LENGTH; i++) {
        padded_csca_pubKey_bytes[i] === extracted_csca_pubKey[i];
    }
}