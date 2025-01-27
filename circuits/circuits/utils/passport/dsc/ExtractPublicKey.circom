pragma circom 2.1.9;
include "@openpassport/zk-email-circuits/utils/array.circom";

template ExtractPublicKey(max_cert_bytes, maxPubkeyBytesLength) {
    signal input raw_dsc_cert[max_cert_bytes];
    signal input dsc_pubKey_offset;
    signal input dsc_pubkey_length_bytes;
    signal output out[maxPubkeyBytesLength];

    //reverse the certificate
    signal raw_dsc_cert_reversed[max_cert_bytes];
    for (var i=0; i<max_cert_bytes; i++) {
        raw_dsc_cert_reversed[i] <== raw_dsc_cert[max_cert_bytes - 1 - i];
    }
    
    component shifter = VarShiftLeft(max_cert_bytes, maxPubkeyBytesLength);
    shifter.in <== raw_dsc_cert_reversed;
    //for ecdsa, dsc_pubkey_length_bytes is x+y length
    shifter.shift <== (max_cert_bytes - dsc_pubKey_offset - dsc_pubkey_length_bytes);

    signal extracted_pubkey[maxPubkeyBytesLength +1];
    extracted_pubkey[maxPubkeyBytesLength] <== 0;
    for (var i=0; i<maxPubkeyBytesLength; i++) {
        extracted_pubkey[i] <== shifter.out[i];
    }
    component selectPubKkey = SelectSubArray(maxPubkeyBytesLength + 1, maxPubkeyBytesLength);
    selectPubKkey.in <== extracted_pubkey;
    selectPubKkey.startIndex <== 0;
    selectPubKkey.length <== dsc_pubkey_length_bytes;

    for (var i=0; i<maxPubkeyBytesLength; i++) {
        out[i] <== selectPubKkey.out[i];
    }
}