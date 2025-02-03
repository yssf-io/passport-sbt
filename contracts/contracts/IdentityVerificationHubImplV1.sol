// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/access/Ownable2StepUpgradeable.sol";
import "./constants/CircuitConstants.sol";
import "./constants/AttestationId.sol";
import "./libraries/Formatter.sol";
import "./libraries/CircuitAttributeHandler.sol";
import "./interfaces/IIdentityVerificationHubV1.sol";
import "./interfaces/IIdentityRegistryV1.sol";
import "./interfaces/IRegisterCircuitVerifier.sol";
import "./interfaces/IVcAndDiscloseCircuitVerifier.sol";
import "./interfaces/IDscCircuitVerifier.sol";
import "./upgradeable/ImplRoot.sol";

/**
 * @notice ⚠️ CRITICAL STORAGE LAYOUT WARNING ⚠️
 * =============================================
 * 
 * This contract uses the UUPS upgradeable pattern which makes storage layout EXTREMELY SENSITIVE.
 * 
 * 🚫 NEVER MODIFY OR REORDER existing storage variables
 * 🚫 NEVER INSERT new variables between existing ones
 * 🚫 NEVER CHANGE THE TYPE of existing variables
 * 
 * ✅ New storage variables MUST be added in one of these two ways ONLY:
 *    1. At the END of the storage layout
 *    2. In a new V2 contract that inherits from this V1
 * 
 * Examples of forbidden changes:
 * - Changing uint256 to uint128
 * - Changing bytes32 to bytes
 * - Changing array type to mapping
 * 
 * For more detailed information about forbidden changes, please refer to:
 * https://docs.openzeppelin.com/upgrades-plugins/writing-upgradeable#modifying-your-contracts
 * 
 * ⚠️ VIOLATION OF THESE RULES WILL CAUSE CATASTROPHIC STORAGE COLLISIONS IN FUTURE UPGRADES ⚠️
 * =============================================
 */

/**
 * @title IdentityVerificationHubStorageV1
 * @notice Storage contract for IdentityVerificationHubImplV1.
 * @dev Inherits from ImplRoot to include upgradeability functionality.
 */
abstract contract IdentityVerificationHubStorageV1 is 
    ImplRoot 
{
    // ====================================================
    // Storage Variables
    // ====================================================
    
    /// @notice Address of the Identity Registry.
    address internal _registry;

    /// @notice Address of the VC and Disclose circuit verifier.
    address internal _vcAndDiscloseCircuitVerifier;

    /// @notice Mapping from signature type to register circuit verifier addresses.
    mapping(uint256 => address) internal _sigTypeToRegisterCircuitVerifiers;

    /// @notice Mapping from signature type to DSC circuit verifier addresses..
    mapping(uint256 => address) internal _sigTypeToDscCircuitVerifiers;
}

/**
 * @title IdentityVerificationHubImplV1
 * @notice Implementation contract for the Identity Verification Hub.
 * @dev Provides functions for registering commitments and verifying groth16 proofs and inclusion proofs.
 */
contract IdentityVerificationHubImplV1 is 
    IdentityVerificationHubStorageV1, 
    IIdentityVerificationHubV1 
{
    using Formatter for uint256;

    uint256 constant MAX_FORBIDDEN_COUNTRIES_LIST_LENGTH = 10;

    // ====================================================
    // Events
    // ====================================================

    /**
     * @notice Emitted when the hub is initialized.
     * @param registry The address of the registry.
     * @param vcAndDiscloseCircuitVerifier The address of the VC and Disclose circuit verifier.
     * @param registerCircuitVerifierIds Array of register circuit verifier ids.
     * @param registerCircuitVerifiers Array of register circuit verifier addresses.
     * @param dscCircuitVerifierIds Array of DSC circuit verifier ids.
     * @param dscCircuitVerifiers Array of DSC circuit verifier addresses.
     */
    event HubInitialized(
        address registry, 
        address vcAndDiscloseCircuitVerifier,
        uint256[] registerCircuitVerifierIds,
        address[] registerCircuitVerifiers,
        uint256[] dscCircuitVerifierIds,
        address[] dscCircuitVerifiers
    );
    /**
     * @notice Emitted when the registry address is updated.
     * @param registry The new registry address.
     */
    event RegistryUpdated(address registry);
    /**
     * @notice Emitted when the VC and Disclose circuit verifier is updated.
     * @param vcAndDiscloseCircuitVerifier The new VC and Disclose circuit verifier address.
     */
    event VcAndDiscloseCircuitUpdated(address vcAndDiscloseCircuitVerifier);
    /**
     * @notice Emitted when a register circuit verifier is updated.
     * @param typeId The signature type id.
     * @param verifier The new verifier address for the register circuit.
     */
    event RegisterCircuitVerifierUpdated(uint256 typeId, address verifier);
    /**
     * @notice Emitted when a DSC circuit verifier is updated.
     * @param typeId The signature type id.
     * @param verifier The new verifier address for the DSC circuit.
     */
    event DscCircuitVerifierUpdated(uint256 typeId, address verifier);

    // ====================================================
    // Errors
    // ====================================================

    /// @notice Thrown when the lengths of provided arrays do not match.
    error LENGTH_MISMATCH();
    /// @notice Thrown when no verifier is set for a signature type.
    error NO_VERIFIER_SET();
    /// @notice Thrown when the current date in the proof is not within a valid range.
    error CURRENT_DATE_NOT_IN_VALID_RANGE();

    error INVALID_OLDER_THAN();
    error INVALID_FORBIDDEN_COUNTRIES();
    error INVALID_OFAC();

    error INVALID_REGISTER_PROOF();
    error INVALID_DSC_PROOF();
    error INVALID_VC_AND_DISCLOSE_PROOF();

    error INVALID_COMMITMENT_ROOT();
    error INVALID_OFAC_ROOT();
    error INVALID_CSCA_ROOT();

    // ====================================================
    // Constructor
    // ====================================================

    /**
     * @notice Constructor that disables initializers.
     * @dev Prevents direct initialization of the implementation contract.
     */
    constructor() {
        _disableInitializers();
    }

    // ====================================================
    // Initializer
    // ====================================================

    /**
     * @notice Initializes the hub implementation.
     * @dev Sets the registry, VC and Disclose circuit verifier address, register circuit verifiers, and DSC circuit verifiers.
     * @param registryAddress The address of the Identity Registry.
     * @param vcAndDiscloseCircuitVerifierAddress The address of the VC and Disclose circuit verifier.
     * @param registerCircuitVerifierIds Array of ids for register circuit verifiers.
     * @param registerCircuitVerifierAddresses Array of addresses for register circuit verifiers.
     * @param dscCircuitVerifierIds Array of ids for DSC circuit verifiers.
     * @param dscCircuitVerifierAddresses Array of addresses for DSC circuit verifiers.
     */
    function initialize(
        address registryAddress, 
        address vcAndDiscloseCircuitVerifierAddress,
        uint256[] memory registerCircuitVerifierIds,
        address[] memory registerCircuitVerifierAddresses, 
        uint256[] memory dscCircuitVerifierIds,
        address[] memory dscCircuitVerifierAddresses
    ) external initializer {
        __ImplRoot_init();
        _registry = registryAddress;
        _vcAndDiscloseCircuitVerifier = vcAndDiscloseCircuitVerifierAddress;
        if (registerCircuitVerifierIds.length != registerCircuitVerifierAddresses.length) {
            revert LENGTH_MISMATCH();
        }
        if (dscCircuitVerifierIds.length != dscCircuitVerifierAddresses.length) {
            revert LENGTH_MISMATCH();
        }
        for (uint256 i = 0; i < registerCircuitVerifierIds.length; i++) {
            _sigTypeToRegisterCircuitVerifiers[registerCircuitVerifierIds[i]] = registerCircuitVerifierAddresses[i];
        }
        for (uint256 i = 0; i < dscCircuitVerifierIds.length; i++) {
            _sigTypeToDscCircuitVerifiers[dscCircuitVerifierIds[i]] = dscCircuitVerifierAddresses[i];
        }
        emit HubInitialized(
            registryAddress, 
            vcAndDiscloseCircuitVerifierAddress,
            registerCircuitVerifierIds,
            registerCircuitVerifierAddresses,
            dscCircuitVerifierIds,
            dscCircuitVerifierAddresses
        );
    }

    // ====================================================
    // External View Functions
    // ====================================================

    /**
     * @notice Retrieves the registry address.
     * @return The address of the Identity Registry.
     */
    function registry() 
        external
        virtual
        onlyProxy
        view 
        returns (address) 
    {
        return _registry;
    }

    /**
     * @notice Retrieves the VC and Disclose circuit verifier address.
     * @return The address of the VC and Disclose circuit verifier.
     */
    function vcAndDiscloseCircuitVerifier() 
        external
        virtual
        onlyProxy
        view 
        returns (address) 
    {
        return _vcAndDiscloseCircuitVerifier;
    }

    /**
     * @notice Retrieves the register circuit verifier address for a given signature type.
     * @param typeId The signature type identifier.
     * @return The register circuit verifier address.
     */
    function sigTypeToRegisterCircuitVerifiers(
        uint256 typeId
    ) 
        external
        virtual
        onlyProxy
        view 
        returns (address) 
    {
        return _sigTypeToRegisterCircuitVerifiers[typeId];
    }

    /**
     * @notice Retrieves the DSC circuit verifier address for a given signature type.
     * @param typeId The signature type identifier.
     * @return The DSC circuit verifier address.
     */
    function sigTypeToDscCircuitVerifiers(
        uint256 typeId
    ) 
        external
        virtual
        onlyProxy
        view 
        returns (address) 
    {
        return _sigTypeToDscCircuitVerifiers[typeId];
    }

    /**
     * @notice Converts packed revealed data into a human-readable format.
     * @dev Uses Formatter and CircuitAttributeHandler to decode the data.
     * @param revealedDataPacked An array of three packed uint256 values.
     * @param types An array of RevealedDataType indicating the types of data expected.
     * @return A ReadableRevealedData struct containing the decoded data.
     */
    function getReadableRevealedData(
        uint256[3] memory revealedDataPacked,
        RevealedDataType[] memory types
    )
        external
        virtual
        onlyProxy
        view
        returns (ReadableRevealedData memory)
    {
        bytes memory charcodes = Formatter.fieldElementsToBytes(
            revealedDataPacked
        );

        ReadableRevealedData memory attrs;

        for (uint256 i = 0; i < types.length; i++) {
            RevealedDataType dataType = types[i];
            if (dataType == RevealedDataType.ISSUING_STATE) {
                attrs.issuingState = CircuitAttributeHandler.getIssuingState(charcodes);
            } else if (dataType == RevealedDataType.NAME) {
                attrs.name = CircuitAttributeHandler.getName(charcodes);
            } else if (dataType == RevealedDataType.PASSPORT_NUMBER) {
                attrs.passportNumber = CircuitAttributeHandler.getPassportNumber(charcodes);
            } else if (dataType == RevealedDataType.NATIONALITY) {
                attrs.nationality = CircuitAttributeHandler.getNationality(charcodes);
            } else if (dataType == RevealedDataType.DATE_OF_BIRTH) {
                attrs.dateOfBirth = CircuitAttributeHandler.getDateOfBirth(charcodes);
            } else if (dataType == RevealedDataType.GENDER) {
                attrs.gender = CircuitAttributeHandler.getGender(charcodes);
            } else if (dataType == RevealedDataType.EXPIRY_DATE) {
                attrs.expiryDate = CircuitAttributeHandler.getExpiryDate(charcodes);
            } else if (dataType == RevealedDataType.OLDER_THAN) {
                attrs.olderThan = CircuitAttributeHandler.getOlderThan(charcodes);
            } else if (dataType == RevealedDataType.OFAC) {
                attrs.ofac = CircuitAttributeHandler.getOfac(charcodes);
            }
        }

        return attrs;
    }

    /**
     * @notice Extracts the forbidden countries list from packed data.
     * @param forbiddenCountriesListPacked Packed data representing forbidden countries.
     * @return An array of strings with a maximum length of MAX_FORBIDDEN_COUNTRIES_LIST_LENGTH.
     */
    function getReadableForbiddenCountries(
        uint256 forbiddenCountriesListPacked
    )
        external
        virtual
        onlyProxy
        view
        returns (string[MAX_FORBIDDEN_COUNTRIES_LIST_LENGTH] memory)
    {
        return Formatter.extractForbiddenCountriesFromPacked(forbiddenCountriesListPacked);
    }

    /**
     * @notice Verifies the VC and Disclose proof.
     * @dev Checks commitment roots, OFAC root, current date range, and other attributes depending on verification configuration.
     * @param proof The VcAndDiscloseHubProof containing the proof data.
     * @return result A VcAndDiscloseVerificationResult struct with the verification results.
     */
    function verifyVcAndDisclose(
        VcAndDiscloseHubProof memory proof
    )
        external
        virtual
        view
        onlyProxy
        returns (VcAndDiscloseVerificationResult memory)
    {
        VcAndDiscloseVerificationResult memory result;
        
        result.identityCommitmentRoot = verifyVcAndDiscloseProof(proof);

        for (uint256 i = 0; i < 3; i++) {
            result.revealedDataPacked[i] = proof.vcAndDiscloseProof.pubSignals[CircuitConstants.VC_AND_DISCLOSE_REVEALED_DATA_PACKED_INDEX + i];
        }
        result.forbiddenCountriesListPacked = proof.vcAndDiscloseProof.pubSignals[CircuitConstants.VC_AND_DISCLOSE_FORBIDDEN_COUNTRIES_LIST_PACKED_INDEX];
        result.nullifier = proof.vcAndDiscloseProof.pubSignals[CircuitConstants.VC_AND_DISCLOSE_NULLIFIER_INDEX];
        result.attestationId = proof.vcAndDiscloseProof.pubSignals[CircuitConstants.VC_AND_DISCLOSE_ATTESTATION_ID_INDEX];
        result.userIdentifier = proof.vcAndDiscloseProof.pubSignals[CircuitConstants.VC_AND_DISCLOSE_USER_IDENTIFIER_INDEX];
        result.scope = proof.vcAndDiscloseProof.pubSignals[CircuitConstants.VC_AND_DISCLOSE_SCOPE_INDEX];
        return result;
    }

    // ====================================================
    // External Update Functions
    // ====================================================

    /**
     * @notice Updates the registry address.
     * @param registryAddress The new registry address.
     */
    function updateRegistry(
        address registryAddress
    ) 
        external 
        virtual
        onlyProxy
        onlyOwner 
    {
        _registry = registryAddress;
        emit RegistryUpdated(registryAddress);
    }

    /**
     * @notice Updates the VC and Disclose circuit verifier address.
     * @param vcAndDiscloseCircuitVerifierAddress The new VC and Disclose circuit verifier address.
     */
    function updateVcAndDiscloseCircuit(
        address vcAndDiscloseCircuitVerifierAddress
    ) 
        external 
        virtual
        onlyProxy
        onlyOwner 
    {
        _vcAndDiscloseCircuitVerifier = vcAndDiscloseCircuitVerifierAddress;
        emit VcAndDiscloseCircuitUpdated(vcAndDiscloseCircuitVerifierAddress);
    }

    /**
     * @notice Updates the register circuit verifier for a specific signature type.
     * @param typeId The signature type identifier.
     * @param verifierAddress The new register circuit verifier address.
     */
    function updateRegisterCircuitVerifier(
        uint256 typeId, 
        address verifierAddress
    ) 
        external 
        virtual
        onlyProxy
        onlyOwner 
    {
        _sigTypeToRegisterCircuitVerifiers[typeId] = verifierAddress;
        emit RegisterCircuitVerifierUpdated(typeId, verifierAddress);
    }

    /**
     * @notice Updates the DSC circuit verifier for a specific signature type.
     * @param typeId The signature type identifier.
     * @param verifierAddress The new DSC circuit verifier address.
     */
    function updateDscVerifier(
        uint256 typeId, 
        address verifierAddress
    ) 
        external 
        virtual
        onlyProxy
        onlyOwner 
    {
        _sigTypeToDscCircuitVerifiers[typeId] = verifierAddress;
        emit DscCircuitVerifierUpdated(typeId, verifierAddress);
    }

    /**
     * @notice Batch updates register circuit verifiers.
     * @param typeIds An array of signature type identifiers.
     * @param verifierAddresses An array of new register circuit verifier addresses.
     */
    function batchUpdateRegisterCircuitVerifiers(
        uint256[] calldata typeIds,
        address[] calldata verifierAddresses
    ) 
        external 
        virtual
        onlyProxy
        onlyOwner 
    {
        if (typeIds.length != verifierAddresses.length) {
            revert LENGTH_MISMATCH();
        }
        for (uint256 i = 0; i < typeIds.length; i++) {
            _sigTypeToRegisterCircuitVerifiers[typeIds[i]] = verifierAddresses[i];
            emit RegisterCircuitVerifierUpdated(typeIds[i], verifierAddresses[i]);
        }
    }

    /**
     * @notice Batch updates DSC circuit verifiers.
     * @param typeIds An array of signature type identifiers.
     * @param verifierAddresses An array of new DSC circuit verifier addresses.
     */
    function batchUpdateDscCircuitVerifiers(
        uint256[] calldata typeIds,
        address[] calldata verifierAddresses
    ) 
        external
        virtual
        onlyProxy
        onlyOwner 
    {
        if (typeIds.length != verifierAddresses.length) {
            revert LENGTH_MISMATCH();
        }
        for (uint256 i = 0; i < typeIds.length; i++) {
            _sigTypeToDscCircuitVerifiers[typeIds[i]] = verifierAddresses[i];
            emit DscCircuitVerifierUpdated(typeIds[i], verifierAddresses[i]);
        }
    }

    // ====================================================
    // External Register Functions
    // ====================================================

    /**
     * @notice Registers a passport commitment using a register circuit proof.
     * @dev Verifies the proof and then calls the Identity Registry to register the commitment.
     * @param registerCircuitVerifierId The identifier for the register circuit verifier to use.
     * @param registerCircuitProof The register circuit proof data.
     */
    function registerPassportCommitment(
        uint256 registerCircuitVerifierId,
        IRegisterCircuitVerifier.RegisterCircuitProof memory registerCircuitProof
    ) 
        external
        virtual
        onlyProxy
    {
        verifyPassportRegisterProof(registerCircuitVerifierId, registerCircuitProof);
        IIdentityRegistryV1(_registry).registerCommitment(
            AttestationId.E_PASSPORT,
            registerCircuitProof.pubSignals[CircuitConstants.REGISTER_NULLIFIER_INDEX],
            registerCircuitProof.pubSignals[CircuitConstants.REGISTER_COMMITMENT_INDEX]
        );
    }

    /**
     * @notice Registers a DSC key commitment using a DSC circuit proof.
     * @dev Verifies the DSC proof and then calls the Identity Registry to register the dsc key commitment.
     * @param dscCircuitVerifierId The identifier for the DSC circuit verifier to use.
     * @param dscCircuitProof The DSC circuit proof data.
     */
    function registerDscKeyCommitment(
        uint256 dscCircuitVerifierId,
        IDscCircuitVerifier.DscCircuitProof memory dscCircuitProof
    )
        external
        virtual
        onlyProxy
    {
        verifyPassportDscProof(dscCircuitVerifierId, dscCircuitProof);
        IIdentityRegistryV1(_registry).registerDscKeyCommitment(
            dscCircuitProof.pubSignals[CircuitConstants.DSC_TREE_LEAF_INDEX]
        );
    }

    // ====================================================
    // Internal Functions
    // ====================================================

    /**
     * @notice Verifies the VC and Disclose proof.
     * @dev Checks commitment roots, OFAC root, current date range, and other attributes depending on verification configuration.
     * @param proof The VcAndDiscloseHubProof containing the proof data.
     * @return identityCommitmentRoot The verified identity commitment root from the proof.
     */
    function verifyVcAndDiscloseProof(
        VcAndDiscloseHubProof memory proof
    ) 
        internal
        view
        returns (uint256 identityCommitmentRoot)
    {
        // verify identity commitment root
        if (!IIdentityRegistryV1(_registry).checkIdentityCommitmentRoot(proof.vcAndDiscloseProof.pubSignals[CircuitConstants.VC_AND_DISCLOSE_MERKLE_ROOT_INDEX])) {
            revert INVALID_COMMITMENT_ROOT();
        }

        // verify current date
        uint[6] memory dateNum;
        for (uint256 i = 0; i < 6; i++) {
            dateNum[i] = proof.vcAndDiscloseProof.pubSignals[CircuitConstants.VC_AND_DISCLOSE_CURRENT_DATE_INDEX + i];
        }

        uint currentTimestamp = Formatter.proofDateToUnixTimestamp(dateNum);
        if(
            currentTimestamp < getStartOfDayTimestamp() - 1 days + 1 ||
            currentTimestamp > getStartOfDayTimestamp() + 1 days - 1
        ) {
            revert CURRENT_DATE_NOT_IN_VALID_RANGE();
        }

        // verify attributes
        uint256[3] memory revealedDataPacked;
        for (uint256 i = 0; i < 3; i++) {
            revealedDataPacked[i] = proof.vcAndDiscloseProof.pubSignals[CircuitConstants.VC_AND_DISCLOSE_REVEALED_DATA_PACKED_INDEX + i];
        }
        if (proof.olderThanEnabled) {
            if (!CircuitAttributeHandler.compareOlderThan(Formatter.fieldElementsToBytes(revealedDataPacked), proof.olderThan)) {
                revert INVALID_OLDER_THAN();
            }
        }
        if (proof.ofacEnabled) {
            if (!CircuitAttributeHandler.compareOfac(Formatter.fieldElementsToBytes(revealedDataPacked))) {
                revert INVALID_OFAC();
            }
            if (!IIdentityRegistryV1(_registry).checkOfacRoot(proof.vcAndDiscloseProof.pubSignals[CircuitConstants.VC_AND_DISCLOSE_SMT_ROOT_INDEX])) {
                revert INVALID_OFAC_ROOT();
            }
        }
        if (proof.forbiddenCountriesEnabled) {
            if (proof.forbiddenCountriesListPacked != proof.vcAndDiscloseProof.pubSignals[CircuitConstants.VC_AND_DISCLOSE_FORBIDDEN_COUNTRIES_LIST_PACKED_INDEX]) {
                revert INVALID_FORBIDDEN_COUNTRIES();
            }
        }

        // verify the proof using the VC and Disclose circuit verifier
        if (!IVcAndDiscloseCircuitVerifier(_vcAndDiscloseCircuitVerifier).verifyProof(proof.vcAndDiscloseProof.a, proof.vcAndDiscloseProof.b, proof.vcAndDiscloseProof.c, proof.vcAndDiscloseProof.pubSignals)) {
            revert INVALID_VC_AND_DISCLOSE_PROOF();
        }

        return proof.vcAndDiscloseProof.pubSignals[CircuitConstants.VC_AND_DISCLOSE_MERKLE_ROOT_INDEX];
    }

    /**
     * @notice Verifies the passport register circuit proof.
     * @dev Uses the register circuit verifier specified by registerCircuitVerifierId.
     * @param registerCircuitVerifierId The identifier for the register circuit verifier.
     * @param registerCircuitProof The register circuit proof data.
     */
    function verifyPassportRegisterProof(
        uint256 registerCircuitVerifierId,
        IRegisterCircuitVerifier.RegisterCircuitProof memory registerCircuitProof
    ) 
        internal
        view
    {
        address verifier = _sigTypeToRegisterCircuitVerifiers[registerCircuitVerifierId];
        if (verifier == address(0)) {
            revert NO_VERIFIER_SET();
        }

        if (!IIdentityRegistryV1(_registry).checkDscKeyCommitmentMerkleRoot(registerCircuitProof.pubSignals[CircuitConstants.REGISTER_MERKLE_ROOT_INDEX])) {
            revert INVALID_COMMITMENT_ROOT();
        }

        if(!IRegisterCircuitVerifier(verifier).verifyProof(
            registerCircuitProof.a,
            registerCircuitProof.b,
            registerCircuitProof.c,
            registerCircuitProof.pubSignals
        )) {
            revert INVALID_REGISTER_PROOF();
        }
    }

    /**
     * @notice Verifies the passport DSC circuit proof.
     * @dev Uses the DSC circuit verifier specified by dscCircuitVerifierId.
     * @param dscCircuitVerifierId The identifier for the DSC circuit verifier.
     * @param dscCircuitProof The DSC circuit proof data.
     */
    function verifyPassportDscProof(
        uint256 dscCircuitVerifierId,
        IDscCircuitVerifier.DscCircuitProof memory dscCircuitProof
    ) 
        internal
        view
    {
        address verifier = _sigTypeToDscCircuitVerifiers[dscCircuitVerifierId];
        if (verifier == address(0)) {
            revert NO_VERIFIER_SET();
        }

        if (!IIdentityRegistryV1(_registry).checkCscaRoot(dscCircuitProof.pubSignals[CircuitConstants.DSC_CSCA_ROOT_INDEX])) {
            revert INVALID_CSCA_ROOT();
        }

        if(!IDscCircuitVerifier(verifier).verifyProof(
            dscCircuitProof.a,
            dscCircuitProof.b,
            dscCircuitProof.c,
            dscCircuitProof.pubSignals
        )) {
            revert INVALID_DSC_PROOF();
        }
    }

    /**
     * @notice Retrieves the timestamp for the start of the current day.
     * @dev Calculated by subtracting the remainder of block.timestamp modulo 1 day.
     * @return The Unix timestamp representing the start of the day.
     */
    function getStartOfDayTimestamp() internal view returns (uint256) {
        return block.timestamp - (block.timestamp % 1 days);
    }
}