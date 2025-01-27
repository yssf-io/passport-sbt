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

// NOTE: this circuit is unaudited and should not be used in production
/// @title SplitBytesToWords
/// @notice split an array of bytes into an array of words
/// @notice useful for casting a message or modulus before RSA verification
/// @param l: number of bytes in the input array
/// @param n: number of bits in a word
/// @param k: number of words
/// @input in: array of bytes
/// @output out: array of words
template SplitBytesToWords (l,n,k) {
    signal input in[l];
    signal output out[k];

    component num2bits[l];
    for (var i = 0 ; i < l ; i++){
        num2bits[i] = Num2Bits(8);
        num2bits[i].in <== in[i];
    }
    component bits2num[k];
    for (var i = 0 ; i < k ; i++){
        bits2num[i] = Bits2Num(n);
        for(var j = 0 ; j < n ; j++){
            if(i*n + j >=  8 * l){
                bits2num[i].in[j] <==  0;
            }
            else{
                bits2num[i].in[j] <== num2bits[l - (( i * n + j) \ 8) - 1].out[ ((i * n + j) % 8)];
            }
        }
    }
    for( var i = 0 ; i< k ; i++){
    out[i] <== bits2num[i].out;
    }
}

/// NOTE: this circuit is unaudited and should not be used in production
/// @title SplitBytesToWords
/// @notice split an array of bytes into an array of words
/// @notice useful for casting a message or modulus before RSA verification
/// @param l: number of bytes in the input array
/// @param n: number of bits in a word
/// @param k: number of words
/// @input in: array of bytes
/// @output out: array of words
template SplitSignalsToWords (t,l,n,k) {
    signal input in[l];
    signal output out[k];
    component num2bits[l];
    for (var i = 0 ; i < l ; i++){
        num2bits[i] = Num2Bits(t);
        num2bits[i].in <== in[i];
    }
    for (var i = 0 ; i < t ; i ++){
    }
    component bits2num[k];
    for (var i = 0 ; i < k ; i++){
        bits2num[i] = Bits2Num(n);

        for(var j = 0 ; j < n ; j++){
            if(i*n + j >= l  * t){
                bits2num[i].in[j] <==  0;
            }
            else{
                bits2num[i].in[j] <== num2bits[ (( i * n + j) \ t) ].out[ ((i * n + j) % t)];
            }
            }
    }
    for( var i = 0 ; i< k ; i++){
    out[i] <== bits2num[i].out;
    }

}