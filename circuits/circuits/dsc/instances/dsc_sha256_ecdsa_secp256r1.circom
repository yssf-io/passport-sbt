pragma circom 2.1.9;

include "../dsc.circom";

component main { public [ merkle_root] } = DSC(8, 64, 4);
