// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/**
 * @title IRegisterCircuitVerifier
 * @notice Interface for verifying register circuit proofs.
 * @dev This interface defines the structure of a register circuit proof and exposes a function to verify such proofs.
 */
interface IRegisterCircuitVerifier {

    /**
     * @notice Represents a register circuit proof.
     * @dev This structure encapsulates the required proof elements.
     * @param a An array of two unsigned integers representing the proof component 'a'.
     * @param b A 2x2 array of unsigned integers representing the proof component 'b'.
     * @param c An array of two unsigned integers representing the proof component 'c'.
     * @param pubSignals An array of three unsigned integers representing the public signals associated with the proof.
     */
    struct RegisterCircuitProof {
        uint[2] a;
        uint[2][2] b;
        uint[2] c;
        uint[3] pubSignals;
    }

    /**
     * @notice Verifies a given register circuit proof.
     * @dev This function checks the validity of the provided proof parameters.
     * @param a The 'a' component of the proof.
     * @param b The 'b' component of the proof.
     * @param c The 'c' component of the proof.
     * @param pubSignals The public signals associated with the proof.
     * @return isValid A boolean value indicating whether the provided proof is valid (true) or not (false).
     */
    function verifyProof (
        uint[2] calldata a,
        uint[2][2] calldata b,
        uint[2] calldata c,
        uint[3] calldata pubSignals
    ) external view returns (bool isValid);
}