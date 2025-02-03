// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/**
 * @title IVcAndDiscloseCircuitVerifier
 * @notice Interface for verifying zero-knowledge proofs related to VC and Disclose circuits.
 * @dev This interface defines the structure of a VC and Disclose proof and a function to verify such proofs.
 */
interface IVcAndDiscloseCircuitVerifier {

    /**
     * @notice Represents a VC and Disclose proof.
     * @param a An array of two unsigned integers representing the proof component 'a'.
     * @param b A 2x2 array of unsigned integers representing the proof component 'b'.
     * @param c An array of two unsigned integers representing the proof component 'c'.
     * @param pubSignals An array of 16 unsigned integers representing the public signals associated with the proof.
     */
    struct VcAndDiscloseProof {
        uint[2] a;
        uint[2][2] b;
        uint[2] c;
        uint[16] pubSignals;
    }

    /**
     * @notice Verifies a given VC and Disclose zero-knowledge proof.
     * @dev This function checks the validity of the provided proof parameters.
     * @param a The 'a' component of the proof.
     * @param b The 'b' component of the proof.
     * @param c The 'c' component of the proof.
     * @param pubSignals The public signals associated with the proof.
     * @return A boolean value indicating whether the proof is valid (true) or not (false).
     */
    function verifyProof (
        uint[2] calldata a,
        uint[2][2] calldata b,
        uint[2] calldata c,
        uint[16] calldata pubSignals
    ) external view returns (bool);
}