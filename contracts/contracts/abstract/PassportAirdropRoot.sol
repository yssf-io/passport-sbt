// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {IIdentityVerificationHubV1} from "../interfaces/IIdentityVerificationHubV1.sol";
import {IVcAndDiscloseCircuitVerifier} from "../interfaces/IVcAndDiscloseCircuitVerifier.sol";
import {IIdentityRegistryV1} from "../interfaces/IIdentityRegistryV1.sol";
import {CircuitConstants} from "../constants/CircuitConstants.sol";
import {IPassportAirdropRoot} from "../interfaces/IPassportAirdropRoot.sol";

/**
 * @title PassportAirdropRoot
 * @notice Abstract contract to manage passport airdrop functionality, including registration with vc and disclose proof.
 * @dev Provides the core registration logic and verification of proofs. Inherits from IPassportAirdropRoot.
 */
abstract contract PassportAirdropRoot is 
    IPassportAirdropRoot
{

    // ====================================================
    // Storage Variables
    // ====================================================
    
    /// @notice Expected scope for the proof verification.
    uint256 internal immutable _scope;
    /// @notice Expected attestation identifier for the identity behind the proof.
    uint256 internal immutable _attestationId;
    /// @notice Target root timestamp used for additional verification.
    uint256 internal immutable _targetRootTimestamp;

    /// @notice Verification configuration settings.
    IPassportAirdropRoot.VerificationConfig internal _verificationConfig;

    /// @notice Instance of the Identity Verification Hub.
    IIdentityVerificationHubV1 internal immutable _identityVerificationHub;
    /// @notice Instance of the Identity Registry.
    IIdentityRegistryV1 internal immutable _identityRegistry;

    /// @notice Mapping recording used nullifiers to prevent double registration.
    mapping(uint256 => uint256) internal _nullifiers;
    /// @notice Mapping tracking registered user identifiers.
    mapping(uint256 => bool) internal _registeredUserIdentifiers;

    // ====================================================
    // Events
    // ====================================================

    /**
     * @notice Emitted when a new user identifier is successfully registered.
     * @param registeredUserIdentifier The user identifier that has been registered.
     * @param nullifier The nullifier associated with the registered commitment.
     */
    event UserIdentifierRegistered(uint256 indexed registeredUserIdentifier, uint256 indexed nullifier);

    // ====================================================
    // Errors
    // ====================================================

    /// @dev Reverts if the provided nullifier has already been registered.
    error RegisteredNullifier();
    /// @dev Reverts if the attestation identifier in the proof is invalid.
    error InvalidAttestationId();
    /// @dev Reverts if the proof scope does not match the expected scope.
    error InvalidScope();
    /// @dev Reverts if the identity root timestamp is not valid.
    error InvalidTimestamp();

    /**
     * @notice Initializes the PassportAirdropRoot contract.
     * @dev Sets up the identity verification hub, identity registry, expected scope, attestation, and timestamp along with verification configuration.
     * @param identityVerificationHub The address of the Identity Verification Hub.
     * @param identityRegistry The address of the Identity Registry.
     * @param scope The expected proof scope.
     * @param attestationId The expected attestation identifier.
     * @param targetRootTimestamp The target timestamp for root verification (set to 0 to disable).
     * @param olderThanEnabled Flag indicating if the 'olderThan' attribute should be verified.
     * @param olderThan Value to compare against for 'olderThan' verification.
     * @param forbiddenCountriesEnabled Flag indicating if forbidden countries verification is enabled.
     * @param forbiddenCountriesListPacked Packed list of forbidden countries.
     * @param ofacEnabled Flag indicating if OFAC verification is enabled.
     */
    constructor(
        address identityVerificationHub, 
        address identityRegistry,
        uint256 scope, 
        uint256 attestationId,
        uint256 targetRootTimestamp,
        bool olderThanEnabled,
        uint256 olderThan,
        bool forbiddenCountriesEnabled,
        uint256 forbiddenCountriesListPacked,
        bool ofacEnabled
    ) {
        _identityVerificationHub = IIdentityVerificationHubV1(identityVerificationHub);
        _identityRegistry = IIdentityRegistryV1(identityRegistry);
        _scope = scope;
        _attestationId = attestationId;
        _targetRootTimestamp = targetRootTimestamp;
        _verificationConfig.olderThanEnabled = olderThanEnabled;
        _verificationConfig.olderThan = olderThan;
        _verificationConfig.forbiddenCountriesEnabled = forbiddenCountriesEnabled;
        _verificationConfig.forbiddenCountriesListPacked = forbiddenCountriesListPacked;
        _verificationConfig.ofacEnabled = ofacEnabled;
    }

    /**
     * @notice Internal function to register a user address based on a valid VC and Disclose proof.
     * @dev Verifies the proof against the expected scope, attestation identifier, and, if applicable,
     *      ensures the identity commitment root was generated at the target timestamp. Records
     *      the nullifier and marks the corresponding user identifier as registered.
     * @param proof The VC and Disclose proof containing public signals and proof data.
     * @return userIdentifier The user identifier extracted from the proof.
     */
    function _registerAddress(
        IVcAndDiscloseCircuitVerifier.VcAndDiscloseProof memory proof
    )
        internal
        returns (uint256 userIdentifier)
    {
        if (_scope != proof.pubSignals[CircuitConstants.VC_AND_DISCLOSE_SCOPE_INDEX]) {
            revert InvalidScope();
        }

        if (_nullifiers[proof.pubSignals[CircuitConstants.VC_AND_DISCLOSE_NULLIFIER_INDEX]] != 0) {
            revert RegisteredNullifier();
        }

        if (_attestationId != proof.pubSignals[CircuitConstants.VC_AND_DISCLOSE_ATTESTATION_ID_INDEX]) {
            revert InvalidAttestationId();
        }

        IIdentityVerificationHubV1.VcAndDiscloseVerificationResult memory result = _identityVerificationHub.verifyVcAndDisclose(
            IIdentityVerificationHubV1.VcAndDiscloseHubProof({
                olderThanEnabled: _verificationConfig.olderThanEnabled,
                olderThan: _verificationConfig.olderThan,
                forbiddenCountriesEnabled: _verificationConfig.forbiddenCountriesEnabled,
                forbiddenCountriesListPacked: _verificationConfig.forbiddenCountriesListPacked,
                ofacEnabled: _verificationConfig.ofacEnabled,
                vcAndDiscloseProof: proof
            })
        );

        if (_targetRootTimestamp != 0) {
            if (_identityRegistry.rootTimestamps(result.identityCommitmentRoot) != _targetRootTimestamp) {
                revert InvalidTimestamp();
            }
        }

        _nullifiers[result.nullifier] = proof.pubSignals[CircuitConstants.VC_AND_DISCLOSE_USER_IDENTIFIER_INDEX];
        _registeredUserIdentifiers[proof.pubSignals[CircuitConstants.VC_AND_DISCLOSE_USER_IDENTIFIER_INDEX]] = true;

        emit UserIdentifierRegistered(proof.pubSignals[CircuitConstants.VC_AND_DISCLOSE_USER_IDENTIFIER_INDEX], result.nullifier);

        return proof.pubSignals[CircuitConstants.VC_AND_DISCLOSE_USER_IDENTIFIER_INDEX];
    }
}
