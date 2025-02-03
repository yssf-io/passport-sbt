pragma circom 2.1.9;

include "../register.circom";

component main { public [ merkle_root ] } = REGISTER(384, 384, 22, 64, 6, 768, 256);