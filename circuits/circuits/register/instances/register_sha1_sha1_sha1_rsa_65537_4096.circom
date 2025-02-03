pragma circom 2.1.9;

include "../register.circom";

component main { public [ merkle_root ] } = REGISTER(160, 160, 3, 120, 35, 384, 128);