// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/**
 * @title AttestationId Library
 * @notice This library provides attestation identifiers used across contracts.
 * @dev Currently, it contains the constant E_PASSPORT which represents the identifier
 * for an E-PASSPORT attestation computed as Poseidon("E-PASSPORT").
 */
library AttestationId {
    /**
     * @notice Identifier for an E-PASSPORT attestation.
     * @dev The identifier is computed based on the hash of "E-PASSPORT" using the Poseidon hash function.
     * Here it is hardcoded as bytes32(uint256(1)) for demonstration purposes.
     */
    bytes32 constant E_PASSPORT = bytes32(uint256(1));
}
