pragma circom 2.1.9;

include "../register.circom";

component main { public [ merkle_root ] } = REGISTER(256, 224, 44, 32, 7, 512, 128);