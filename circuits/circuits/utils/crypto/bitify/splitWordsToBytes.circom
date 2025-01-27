pragma circom 2.1.9;
include "circomlib/circuits/bitify.circom";

template WordsToBytes(n_words, k_words, maxBytesLength) {
    assert(n_words * k_words == maxBytesLength * 8);

    signal input words[k_words];
    signal output bytes[maxBytesLength];

    component num2bits[k_words];
    signal word_bits[k_words * n_words];

    // Convert words to bits
    for (var i = 0; i < k_words; i++) {
        num2bits[i] = Num2Bits(n_words);
        num2bits[i].in <== words[i];
    }
    for (var i = 0; i < k_words; i++) {
        for (var j = 0; j < n_words; j++) {
            word_bits[i * n_words + j] <== num2bits[i].out[j];
        }
    }

    // Convert bits back to bytes
    component bits2Num[maxBytesLength];
    for (var i = 0; i < maxBytesLength; i++) {
        bits2Num[i] = Bits2Num(8);
        for (var j = 0; j < 8; j++) {
            bits2Num[i].in[j] <== word_bits[i * 8 + j];
        }
        bytes[i] <== bits2Num[i].out;
    }
}

template WordsToBytesPadded(n_words, k_words, maxBytesLength, paddedLength) {
    assert(n_words * k_words == maxBytesLength * 8);

    signal input words[k_words];
    signal bytes[maxBytesLength];
    signal output paddedBytes[paddedLength];

    component num2bits[k_words];
    signal word_bits[k_words * n_words];

    // Convert words to bits
    for (var i = 0; i < k_words; i++) {
        num2bits[i] = Num2Bits(n_words);
        num2bits[i].in <== words[i];
    }
    for (var i = 0; i < k_words; i++) {
        for (var j = 0; j < n_words; j++) {
            word_bits[i * n_words + j] <== num2bits[i].out[j];
        }
    }

    // Convert bits back to bytes
    component bits2Num[maxBytesLength];
    for (var i = 0; i < maxBytesLength; i++) {
        bits2Num[i] = Bits2Num(8);
        for (var j = 0; j < 8; j++) {
            bits2Num[i].in[j] <== word_bits[i * 8 + j];
        }
        bytes[i] <== bits2Num[i].out;
    }

    for (var i = 0; i < paddedLength; i++) {
        paddedBytes[i] <== bytes[maxBytesLength - i - 1];

    }

}
