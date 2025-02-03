pragma circom 2.1.9;

include "../register.circom";

component main { public [ merkle_root ] } = REGISTER(512, 512, 29, 64, 8, 896, 256);