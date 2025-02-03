// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/**
 * @title IDscCircuitVerifier
 * @notice Interface for verifying zero-knowledge proofs related to the DSC circuit.
 * @dev This interface defines the structure of a DSC circuit proof and exposes a function to verify such proofs.
 */
interface IDscCircuitVerifier {

    /**
     * @notice Represents a DSC circuit proof.
     * @param a An array of two unsigned integers representing the proof component 'a'.
     * @param b A 2x2 array of unsigned integers representing the proof component 'b'.
     * @param c An array of two unsigned integers representing the proof component 'c'.
     * @param pubSignals An array of two unsigned integers representing the public signals associated with the proof.
     */
    struct DscCircuitProof {
        uint[2] a;
        uint[2][2] b;
        uint[2] c;
        uint[2] pubSignals;
    }

    /**
     * @notice Verifies a given DSC circuit zero-knowledge proof.
     * @dev This function checks the validity of the provided DSC proof parameters.
     * @param _pA The 'a' component of the proof.
     * @param _pB The 'b' component of the proof.
     * @param _pC The 'c' component of the proof.
     * @param _pubSignals The public signals associated with the proof.
     * @return A boolean value indicating whether the provided proof is valid (true) or not (false).
     */
    function verifyProof (
        uint[2] calldata _pA,
        uint[2][2] calldata _pB,
        uint[2] calldata _pC,
        uint[2] calldata _pubSignals
    ) external view returns (bool);
}