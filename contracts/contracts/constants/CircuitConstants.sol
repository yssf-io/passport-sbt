//SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

library CircuitConstants {
    uint256 constant REGISTER_NULLIFIER_INDEX = 0;
    uint256 constant REGISTER_COMMITMENT_INDEX = 1;
    uint256 constant REGISTER_GLUE_INDEX = 2;

    uint256 constant DSC_GLUE_INDEX = 0;
    uint256 constant DSC_CSCA_ROOT_INDEX = 1;

    uint256 constant VC_AND_DISCLOSE_REVEALED_DATA_PACKED_INDEX = 0;
    uint256 constant VC_AND_DISCLOSE_FORBIDDEN_COUNTRIES_LIST_PACKED_INDEX = 3;
    uint256 constant VC_AND_DISCLOSE_NULLIFIER_INDEX = 4;
    uint256 constant VC_AND_DISCLOSE_ATTESTATION_ID_INDEX = 5;
    uint256 constant VC_AND_DISCLOSE_SCOPE_INDEX = 6;
    uint256 constant VC_AND_DISCLOSE_MERKLE_ROOT_INDEX = 7;
    uint256 constant VC_AND_DISCLOSE_CURRENT_DATE_INDEX = 8;
    uint256 constant VC_AND_DISCLOSE_SMT_ROOT_INDEX = 14;
    uint256 constant VC_AND_DISCLOSE_USER_IDENTIFIER_INDEX = 15;
}