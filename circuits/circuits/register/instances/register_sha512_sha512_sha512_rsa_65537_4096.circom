pragma circom 2.1.9;

include "../register.circom";

component main { public [ merkle_root ] } = REGISTER(512, 512, 15, 120, 35, 896, 256);
