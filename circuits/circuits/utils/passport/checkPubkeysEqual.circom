pragma circom 2.1.9;

include "../crypto/bitify/bytes.circom";
include "../crypto/bitify/splitWordsToBytes.circom";

/// @title CheckPubkeysEqual
/// @notice Checks if the CSCA public key given is the same as the one in the certificate
/// @param kScaled Number of chunks the given key is split into.
/// @param MAX_CSCA_PUBKEY_LENGTH Maximum length of the parsed CSCA public key
/// @input csca_pubKey CSCA public key given by the user, formatted for signature verification
/// @input extracted_csca_pubKey CSCA public key extracted from the certificate
template CheckPubkeysEqual(n, kScaled, kLengthFactor, MAX_CSCA_PUBKEY_LENGTH) {
    signal input csca_pubKey[kScaled];
    signal input extracted_csca_pubKey[MAX_CSCA_PUBKEY_LENGTH];
    signal input csca_pubKey_actual_size;

    signal csca_pubKey_bytes[MAX_CSCA_PUBKEY_LENGTH] <== WordsToBytes(n, kScaled, n * kScaled / 8)(csca_pubKey);

    // reverse bytes order
    signal reversed_csca_pubKey_bytes[MAX_CSCA_PUBKEY_LENGTH];
    for (var i = 0; i < MAX_CSCA_PUBKEY_LENGTH; i++) {
        reversed_csca_pubKey_bytes[i] <== csca_pubKey_bytes[MAX_CSCA_PUBKEY_LENGTH - i - 1];
    }

    signal shifted_csca_pubKey_bytes[MAX_CSCA_PUBKEY_LENGTH] <== VarShiftLeft(MAX_CSCA_PUBKEY_LENGTH, MAX_CSCA_PUBKEY_LENGTH)(
        reversed_csca_pubKey_bytes,
        MAX_CSCA_PUBKEY_LENGTH - csca_pubKey_actual_size
    );

    // if kLengthFactor = 1 it's rsa, if kLengthFactor = 2 it's ecdsa
    // if it's ecdsa, the position of the x and y coordinates are swapped
    // in ecdsa, MAX_CSCA_PUBKEY_LENGTH is always the size of the key
    if (kLengthFactor == 2) {
        for (var i = 0; i < MAX_CSCA_PUBKEY_LENGTH / 2; i++) {
            shifted_csca_pubKey_bytes[i] === extracted_csca_pubKey[MAX_CSCA_PUBKEY_LENGTH / 2 + i];
        }

        for (var i = 0; i < MAX_CSCA_PUBKEY_LENGTH / 2; i++) {
            shifted_csca_pubKey_bytes[MAX_CSCA_PUBKEY_LENGTH / 2 + i] === extracted_csca_pubKey[i];
        }
    // if it's rsa, we just check if the keys are the same
    // in rsa, csca_pubKey_actual_size is the size of the key in bytes
    } else {
        component lessThans[MAX_CSCA_PUBKEY_LENGTH];
        for (var i = 0; i < MAX_CSCA_PUBKEY_LENGTH; i++) {
            lessThans[i] = LessThan(14);
            lessThans[i].in[0] <== i;
            lessThans[i].in[1] <== csca_pubKey_actual_size;

            // If i < csca_pubKey_actual_size => must match
            // If i >= csca_pubKey_actual_size => no constraint
            (shifted_csca_pubKey_bytes[i] - extracted_csca_pubKey[i]) * lessThans[i].out === 0;
        }
    }
}