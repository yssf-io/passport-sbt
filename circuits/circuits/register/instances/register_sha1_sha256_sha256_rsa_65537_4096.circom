pragma circom 2.1.9;

include "../register.circom";

component main { public [ merkle_root ] } = REGISTER(160, 256, 1, 120, 35, 384, 128);