pragma circom 2.1.9;

include "../dsc.circom";

component main { public [  merkle_root] } = DSC(7, 64, 4);
