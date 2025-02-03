// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import "./IRegisterCircuitVerifier.sol";
import "./IDscCircuitVerifier.sol";
import "./IVcAndDiscloseCircuitVerifier.sol";
import "../constants/CircuitConstants.sol";

/**
 * @title IIdentityVerificationHubV1
 * @notice Interface for the Identity Verification Hub for verifying zero-knowledge proofs using VC and Disclose circuits.
 * @dev Defines data structures and external functions for verifying proofs and recovering human-readable data.
 */
interface IIdentityVerificationHubV1 {

    /**
     * @notice Enum representing types of data that may be revealed.
     */
    enum RevealedDataType {
        ISSUING_STATE,     // The issuing state of the passport.
        NAME,              // The full name of the passport holder.
        PASSPORT_NUMBER,   // The passport number.
        NATIONALITY,       // The nationality.
        DATE_OF_BIRTH,     // The date of birth.
        GENDER,            // The gender.
        EXPIRY_DATE,       // The passport expiry date.
        OLDER_THAN,        // The "older than" age verification value.
        OFAC               // The OFAC status (e.g., designated persons/entities).
    }

    /**
     * @notice Structure representing the verification result of a VC and Disclose proof.
     * @param attestationId The attestation identifier from the proof.
     * @param scope The scope of the verification.
     * @param userIdentifier Unique identifier for the user.
     * @param nullifier A value used to prevent double registration.
     * @param identityCommitmentRoot The root of the identity commitment.
     * @param revealedDataPacked Packed revealed data.
     * @param forbiddenCountriesListPacked Packed forbidden countries list.
     */
    struct VcAndDiscloseVerificationResult {
        uint256 attestationId;
        uint256 scope;
        uint256 userIdentifier;
        uint256 nullifier;
        uint256 identityCommitmentRoot;
        uint256[3] revealedDataPacked;
        uint256 forbiddenCountriesListPacked;
    }

    /**
     * @notice Structure representing human-readable revealed data after unpacking.
     * @param issuingState The issuing state as a string.
     * @param name Array of strings representing the passport holder's name.
     * @param passportNumber The passport number.
     * @param nationality The nationality.
     * @param dateOfBirth Formatted date of birth.
     * @param gender The gender.
     * @param expiryDate Formatted expiration date.
     * @param olderThan The verified "older than" age.
     * @param ofac The OFAC verification result.
     */
    struct ReadableRevealedData {
        string issuingState;
        string[] name;
        string passportNumber;
        string nationality;
        string dateOfBirth;
        string gender;
        string expiryDate;
        uint256 olderThan;
        uint256 ofac;
    }

    /**
     * @notice Structure representing a hub proof for VC and Disclose verification.
     * @param olderThanEnabled Flag indicating if the 'olderThan' check is required.
     * @param olderThan Threshold age for verification.
     * @param forbiddenCountriesEnabled Flag indicating if forbidden countries verification is required.
     * @param forbiddenCountriesListPacked Packed forbidden countries list.
     * @param ofacEnabled Flag indicating if the OFAC check is required.
     * @param vcAndDiscloseProof The underlying VC and Disclose proof.
     */
    struct VcAndDiscloseHubProof {
        bool olderThanEnabled;
        uint256 olderThan;
        bool forbiddenCountriesEnabled;
        uint256 forbiddenCountriesListPacked;
        bool ofacEnabled;
        IVcAndDiscloseCircuitVerifier.VcAndDiscloseProof vcAndDiscloseProof;
    }

    /**
     * @notice Verifies a VC and Disclose proof.
     * @dev Checks the provided proof against verification configuration and returns key result data.
     * @param proof The hub proof containing configuration flags and the underlying VC and Disclose proof.
     * @return result The verification result including attestationId, scope, userIdentifier, nullifier, identityCommitmentRoot, revealed data, and forbidden countries list.
     */
    function verifyVcAndDisclose(
        VcAndDiscloseHubProof memory proof
    )
        external
        view
        returns (VcAndDiscloseVerificationResult memory result);

    /**
     * @notice Converts packed revealed data into a human-readable format.
     * @dev Uses an array of RevealedDataType to determine which attributes to extract from the packed data.
     * @param revealedDataPacked An array of three uint256 containing the packed data.
     * @param types An array of RevealedDataType indicating the order of attributes.
     * @return readableData The decoded and formatted revealed data.
     */
    function getReadableRevealedData(
        uint256[3] memory revealedDataPacked,
        RevealedDataType[] memory types
    )
        external
        view
        returns (ReadableRevealedData memory readableData);

    /**
     * @notice Retrieves a human-readable list of forbidden countries.
     * @dev Converts the packed forbidden countries list into a fixed-size array of strings.
     * @param forbiddenCountriesListPacked The packed representation of forbidden countries.
     * @return forbiddenCountries A fixed-size array (length defined by CircuitConstants.MAX_FORBIDDEN_COUNTRIES_LIST_LENGTH) of strings representing forbidden countries.
     */
    function getReadableForbiddenCountries(
        uint256 forbiddenCountriesListPacked
    )
        external
        view
        returns (string[10] memory forbiddenCountries);

    /**
     * @notice Registers a passport commitment using a register circuit proof.
     * @dev Verifies the register circuit proof before registering the passport commitment.
     * @param registerCircuitVerifierId The identifier for the register circuit verifier to be used.
     * @param registerCircuitProof The proof data for the register circuit.
     */
    function registerPassportCommitment(
        uint256 registerCircuitVerifierId,
        IRegisterCircuitVerifier.RegisterCircuitProof memory registerCircuitProof
    )
        external;

    /**
     * @notice Registers a DSC key commitment using a DSC circuit proof.
     * @dev Verifies the DSC circuit proof before registering the DSC key commitment.
     * @param dscCircuitVerifierId The identifier for the DSC circuit verifier to be used.
     * @param dscCircuitProof The proof data for the DSC circuit.
     */
    function registerDscKeyCommitment(
        uint256 dscCircuitVerifierId,
        IDscCircuitVerifier.DscCircuitProof memory dscCircuitProof
    )
        external;

    /**
     * @notice Returns the address of the Identity Registry.
     * @return registryAddr The address of the Identity Registry contract.
     */
    function registry() external view returns (address registryAddr);

    /**
     * @notice Returns the address of the VC and Disclose circuit verifier.
     * @return verifierAddr The address of the VC and Disclose circuit verifier.
     */
    function vcAndDiscloseCircuitVerifier() external view returns (address verifierAddr);

    /**
     * @notice Retrieves the register circuit verifier for a given signature type.
     * @param typeId The signature type identifier.
     * @return verifier The address of the register circuit verifier.
     */
    function sigTypeToRegisterCircuitVerifiers(
        uint256 typeId
    )
        external
        view
        returns (address verifier);

    /**
     * @notice Retrieves the DSC circuit verifier for a given signature type.
     * @param typeId The signature type identifier.
     * @return verifier The address of the DSC circuit verifier.
     */
    function sigTypeToDscCircuitVerifiers(
        uint256 typeId
    )
        external
        view
        returns (address verifier);
} 