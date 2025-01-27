pragma circom 2.1.9;

/// @title Constants
/// @notice Contains constants for the passport circuit

/// @notice Maximum length of the DSC public key — currently 512 bytes padded to 525
function getMaxDscPubKeyLength(){
    return 525;
}
