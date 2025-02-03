// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/**
 * @title Circuit Constants Library
 * @notice This library defines constants representing indices used to access public signals
 *         of various circuits such as register, DSC, and VC/Disclose.
 * @dev These indices map directly to specific data fields in the corresponding circuits proofs.
 */
library CircuitConstants {
    
    // ---------------------------
    // Register Circuit Constants
    // ---------------------------
    
    /**
     * @notice Index to access the nullifier in the register circuit public signals.
     */
    uint256 constant REGISTER_NULLIFIER_INDEX = 0;
    
    /**
     * @notice Index to access the commitment in the register circuit public signals.
     */
    uint256 constant REGISTER_COMMITMENT_INDEX = 1;
    
    /**
     * @notice Index to access the Merkle root in the register circuit public signals.
     */
    uint256 constant REGISTER_MERKLE_ROOT_INDEX = 2;
    
    // ---------------------------
    // DSC Circuit Constants
    // ---------------------------
    
    /**
     * @notice Index to access the tree leaf in the DSC circuit public signals.
     */
    uint256 constant DSC_TREE_LEAF_INDEX = 0;
    
    /**
     * @notice Index to access the CSCA root in the DSC circuit public signals.
     */
    uint256 constant DSC_CSCA_ROOT_INDEX = 1;
    
    // -------------------------------------
    // VC and Disclose Circuit Constants
    // -------------------------------------
    
    /**
     * @notice Index to access the packed revealed data in the VC and Disclose circuit public signals.
     */
    uint256 constant VC_AND_DISCLOSE_REVEALED_DATA_PACKED_INDEX = 0;
    
    /**
     * @notice Index to access the forbidden countries list (packed) in the VC and Disclose circuit public signals.
     */
    uint256 constant VC_AND_DISCLOSE_FORBIDDEN_COUNTRIES_LIST_PACKED_INDEX = 3;
    
    /**
     * @notice Index to access the nullifier in the VC and Disclose circuit public signals.
     */
    uint256 constant VC_AND_DISCLOSE_NULLIFIER_INDEX = 4;
    
    /**
     * @notice Index to access the attestation ID in the VC and Disclose circuit public signals.
     */
    uint256 constant VC_AND_DISCLOSE_ATTESTATION_ID_INDEX = 5;
    
    /**
     * @notice Index to access the Merkle root in the VC and Disclose circuit public signals.
     */
    uint256 constant VC_AND_DISCLOSE_MERKLE_ROOT_INDEX = 6;
    
    /**
     * @notice Index to access the current date in the VC and Disclose circuit public signals.
     */
    uint256 constant VC_AND_DISCLOSE_CURRENT_DATE_INDEX = 7;
    
    /**
     * @notice Index to access the SMT (Sparse Merkle Tree) root in the VC and Disclose circuit public signals.
     */
    uint256 constant VC_AND_DISCLOSE_SMT_ROOT_INDEX = 13;
    
    /**
     * @notice Index to access the scope in the VC and Disclose circuit public signals.
     */
    uint256 constant VC_AND_DISCLOSE_SCOPE_INDEX = 14;
    
    /**
     * @notice Index to access the user identifier in the VC and Disclose circuit public signals.
     */
    uint256 constant VC_AND_DISCLOSE_USER_IDENTIFIER_INDEX = 15;

}