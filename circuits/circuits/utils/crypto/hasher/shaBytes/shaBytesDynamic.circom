pragma circom 2.1.9;

include "./dynamic/sha1Bytes.circom";
include "./dynamic/sha224Bytes.circom";
include "@openpassport/zk-email-circuits/lib/sha.circom";
include "./dynamic/sha384Bytes.circom";
include "./dynamic/sha512Bytes.circom";

/// @title ShaBytesDynamic
/// @notice Computes the hash of an input message using a specified hash length and padded input
/// @param hashLen Desired length of the hash in bits (e.g., 512, 384, 256, 224, 160)
/// @param max_num_bytes Maximum number of bytes in the padded input
/// @input in_padded Padded input message, represented as an array of bits
/// @input in_len_padded_bytes Length of the padded input in bytes
/// @output hash The computed hash of the input message, with length specified by `hashLen`
template ShaBytesDynamic(hashLen, max_num_bytes) {
    signal input in_padded[max_num_bytes];
    signal input in_len_padded_bytes;

    signal output hash_bits[hashLen];

    if (hashLen == 512) {
        hash_bits <== Sha512Bytes(max_num_bytes)(in_padded, in_len_padded_bytes);
    }
    if (hashLen == 384) {
        hash_bits <== Sha384Bytes(max_num_bytes)(in_padded, in_len_padded_bytes);
    }
    if (hashLen == 256) {
        hash_bits <== Sha256Bytes(max_num_bytes)(in_padded, in_len_padded_bytes);
    }
    if (hashLen == 224) { 
        hash_bits <== Sha224Bytes(max_num_bytes)(in_padded, in_len_padded_bytes);
    }
    if (hashLen == 160) {
        hash_bits <== Sha1Bytes(max_num_bytes)(in_padded, in_len_padded_bytes);
    }

}