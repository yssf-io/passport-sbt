pragma circom 2.1.9;

include "../register.circom";

component main { public [ merkle_root ] } = REGISTER(384, 384, 38, 64, 8, 768, 256);