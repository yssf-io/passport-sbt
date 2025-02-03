pragma circom 2.1.9;

/// @title Constants
/// @notice Contains constants for the passport circuit

/// @notice Maximum length of DSC certificate — currently 1792 bytes
/// @dev Empirically, we saw DSCs up to 1591 bytes.
function getMaxDSCLength(){
    return 1792;
}

/// @notice Maximum length of CSCA certificate — currently 1792 bytes.
/// @dev Empirically, we saw CSCAs up to 1671 bytes in the master list.
function getMaxCSCALength(){
    return 1792;
}

/// @notice Maximum number of levels in the CSCA Merkle tree — currently 12
function getMaxCSCALevels(){
    return 12;
}

/// @notice Maximum number of levels in the DSC Merkle tree — currently 12
function getMaxDSCLevels(){
    return 21;
}