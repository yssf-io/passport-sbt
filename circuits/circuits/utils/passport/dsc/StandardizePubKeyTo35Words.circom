pragma circom 2.1.9;
include "../../crypto/bitify/bytes.circom";

template StandardizePubKeyTo35Words(maxPubkeyBytesLength) {
    signal input in[maxPubkeyBytesLength];
    signal output out[35];

    var n_dsc = 120;
    var k_dsc = 35;
    
    component splitToWords = SplitBytesToWords(maxPubkeyBytesLength, n_dsc, k_dsc);
    splitToWords.in <== in;
    
    for (var i=0; i < 35; i++) {
        out[i] <== splitToWords.out[i];
    }
}