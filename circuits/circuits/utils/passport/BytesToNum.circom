pragma circom 2.1.9;

include "circomlib/circuits/bitify.circom";

// Converts 4 bytes into a single number
// Each byte must be in range [0,255]
template BytesToNum() {
    signal input bytes[4];  // Assuming MSB first ordering
    signal output out;
    
    // First convert each byte to bits
    component byte0 = Num2Bits(8);
    component byte1 = Num2Bits(8);
    component byte2 = Num2Bits(8);
    component byte3 = Num2Bits(8);
    
    byte0.in <== bytes[0];
    byte1.in <== bytes[1];
    byte2.in <== bytes[2];
    byte3.in <== bytes[3];
    
    // Now combine all bits into a single number
    component bits2Num = Bits2Num(32);
    
    // Connect in LSB to MSB order (reverse byte order from before)
    for (var i = 0; i < 8; i++) {
        bits2Num.in[i] <== byte3.out[i];       // Least significant byte
        bits2Num.in[8+i] <== byte2.out[i];     // Third byte  
        bits2Num.in[16+i] <== byte1.out[i];    // Second byte
        bits2Num.in[24+i] <== byte0.out[i];    // Most significant byte
    }
    
    // The final output
    out <== bits2Num.out;
}