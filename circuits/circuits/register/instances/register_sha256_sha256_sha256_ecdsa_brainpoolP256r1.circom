pragma circom 2.1.9;

include "../register.circom";

component main { public [ merkle_root ] } = REGISTER(256, 256, 21, 64, 4, 512, 128);