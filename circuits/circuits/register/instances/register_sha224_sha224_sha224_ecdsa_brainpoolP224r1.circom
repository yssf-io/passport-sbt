pragma circom 2.1.9;

include "../register.circom";

component main { public [ merkle_root ] } = REGISTER(224, 224, 30, 32, 7, 512, 128);