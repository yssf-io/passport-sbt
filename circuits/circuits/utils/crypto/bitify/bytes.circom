pragma circom 2.1.9;

template BitsToBytesArray(bits_len){
    var bytes_len = bits_len / 8;
    component b2n[bytes_len];
    signal input in[bits_len];
    signal output out[bytes_len];
    for (var i = 0; i < bytes_len; i++) {
        b2n[i] = Bits2Num(8);
        for (var j = 0; j < 8; j++) {
            b2n[i].in[7 - j] <== in[i * 8 + j];
        }
        out[i] <== b2n[i].out;
    }
}

template BytesToBitsArray(bytes_len){
    var bits_len = bytes_len * 8;
    signal input in[bytes_len];
    signal output out[bits_len];
    component n2b[bytes_len];
    for (var i = 0; i < bytes_len; i++) {
        n2b[i] = Num2Bits(8);
        n2b[i].in <== in[i];
        for (var j = 0; j < 8; j++) {
            out[i * 8 + j] <== n2b[i].out[7 - j];
        }
    }
}