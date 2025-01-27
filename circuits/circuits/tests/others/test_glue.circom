pragma circom 2.1.9;

include "circomlib/circuits/bitify.circom";
include "../../utils/crypto/hasher/shaBytes/shaBytesDynamic.circom";
include "circomlib/circuits/comparators.circom";
include "../../utils/crypto/hasher/hash.circom";
include "circomlib/circuits/poseidon.circom";
include "@zk-kit/binary-merkle-root.circom/src/binary-merkle-root.circom";
include "../../utils/passport/customHashers.circom";
include "../../utils/passport/signatureAlgorithm.circom";
include "../../utils/passport/signatureVerifier.circom";
include "@openpassport/zk-email-circuits/utils/bytes.circom";
include "../../utils/crypto/bitify/bytes.circom";
// include "../../utils/crypto/utils/WordToBytes.circom";
include "../../utils/passport/dsc/StandardizePubKeyTo35Words.circom";
include "../../register/register.circom";


template HashComputationTest(kLengthFactor, n, k, kScaled) {
    var maxPubkeyBytesLength = 525;    
    // Inputs
    signal input pubKey_dsc[kScaled];
    signal input pubkey_dsc_padded[maxPubkeyBytesLength];
    signal input salt;
    signal input pubKey_csca_hash;

    component standardizedDSCPubKey = StandardizeDSCPubKey(n, k, kLengthFactor);
    standardizedDSCPubKey.pubKey_dsc <== pubKey_dsc;
    signal standardizedDSCPubKeyOut[35] <== standardizedDSCPubKey.out;
    signal output register_hash <== CustomHasher(35)(standardizedDSCPubKeyOut);


    signal standardizedDSCPubKeySignal[35] <== StandardizePubKeyTo35Words(maxPubkeyBytesLength)(pubkey_dsc_padded);
    signal output dsc_hash <== CustomHasher(35)(standardizedDSCPubKeySignal);

    register_hash === dsc_hash;
}