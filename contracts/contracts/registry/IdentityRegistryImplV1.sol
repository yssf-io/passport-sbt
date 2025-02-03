// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/access/Ownable2StepUpgradeable.sol";
import "@openzeppelin/contracts/utils/Strings.sol";
import { InternalLeanIMT, LeanIMTData } from "@zk-kit/imt.sol/internal/InternalLeanIMT.sol";
import "../interfaces/IIdentityRegistryV1.sol";
import "../interfaces/IIdentityVerificationHubV1.sol";
import "../upgradeable/ImplRoot.sol";
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
 * ✅ It is safe to rename variables (e.g., changing 'variable' to 'oldVariable')
 *    as long as the type and order remain the same
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
 * @title IdentityRegistryStorageV1
 * @dev Abstract contract for storage layout of IdentityRegistryImplV1.
 * Inherits from ImplRoot to provide upgradeable functionality.
 */
abstract contract IdentityRegistryStorageV1 is
    ImplRoot
{
    // ====================================================
    // Storage Variables
    // ====================================================

    /// @notice Address of the identity verification hub.
    address internal _hub;

    /// @notice Merkle tree data structure for identity commitments.
    LeanIMTData internal _identityCommitmentIMT;

    /// @notice Mapping from Merkle tree root to its creation timestamp.
    mapping(uint256 => uint256) internal _rootTimestamps;

    /// @notice Mapping from attestation ID and nullifier to a boolean indicating registration.
    /// @dev Example: For passport, the attestation id is 1.
    mapping(bytes32 => mapping(uint256 => bool)) internal _nullifiers;

    /// @notice Merkle tree data structure for DSC key commitments.
    LeanIMTData internal _dscKeyCommitmentIMT;

    /// @notice Mapping to determine if a DSC key commitment is registered.
    mapping(uint256 => bool) internal _isRegisteredDscKeyCommitment;

    /// @notice Current OFAC SMT root.
    uint256 internal _ofacRoot;

    /// @notice Current CSCA root.
    uint256 internal _cscaRoot;
}

/**
 * @title IdentityRegistryImplV1
 * @notice Provides functions to register and manage identity commitments using a Merkle tree structure.
 * @dev Inherits from IdentityRegistryStorageV1 and implements IIdentityRegistryV1.
 */
contract IdentityRegistryImplV1 is 
    IdentityRegistryStorageV1,  
    IIdentityRegistryV1 
{
    using InternalLeanIMT for LeanIMTData;

    // ====================================================
    // Events
    // ====================================================

    /// @notice Emitted when the registry is initialized.
    event RegistryInitialized(address hub);
    /// @notice Emitted when the hub address is updated.
    event HubUpdated(address hub);
    /// @notice Emitted when the CSCA root is updated.
    event CscaRootUpdated(uint256 cscaRoot);
    /// @notice Emitted when the OFAC root is updated.
    event OfacRootUpdated(uint256 ofacRoot);
    /// @notice Emitted when an identity commitment is successfully registered.
    event CommitmentRegistered(bytes32 indexed attestationId, uint256 indexed nullifier, uint256 indexed commitment, uint256 timestamp, uint256 imtRoot, uint256 imtIndex);
    /// @notice Emitted when a DSC key commitment is successfully registered.
    event DscKeyCommitmentRegistered(uint256 indexed commitment, uint256 timestamp, uint256 imtRoot, uint256 imtIndex);
    /// @notice Emitted when a identity commitment is added by dev team.
    event DevCommitmentRegistered(bytes32 indexed attestationId, uint256 indexed nullifier, uint256 indexed commitment, uint256 timestamp, uint256 imtRoot, uint256 imtIndex);
    /// @notice Emitted when a identity commitment is updated by dev team.
    event DevCommitmentUpdated(uint256 indexed oldLeaf, uint256 indexed newLeaf, uint256 imtRoot, uint256 timestamp);
    /// @notice Emitted when a identity commitment is removed by dev team.
    event DevCommitmentRemoved(uint256 indexed oldLeaf, uint256 imtRoot, uint256 timestamp);
    /// @notice Emitted when a DSC key commitment is added by dev team.
    event DevDscKeyCommitmentRegistered(uint256 indexed commitment, uint256 imtRoot, uint256 imtIndex);
    /// @notice Emitted when a DSC key commitment is updated by dev team.
    event DevDscKeyCommitmentUpdated(uint256 indexed oldLeaf, uint256 indexed newLeaf, uint256 imtRoot);
    /// @notice Emitted when a DSC key commitment is removed by dev team.
    event DevDscKeyCommitmentRemoved(uint256 indexed oldLeaf, uint256 imtRoot);
    /// @notice Emitted when the state of a nullifier is changed by dev team.
    event DevNullifierStateChanged(bytes32 indexed attestationId, uint256 indexed nullifier, bool state);
    /// @notice Emitted when the state of a DSC key commitment is changed by dev team.
    event DevDscKeyCommitmentStateChanged(uint256 indexed commitment, bool state);

    // ====================================================
    // Errors
    // ====================================================

    /// @notice Thrown when the hub is not set.
    error HUB_NOT_SET();
    /// @notice Thrown when a function is accessed by an address other than the designated hub.
    error ONLY_HUB_CAN_ACCESS();
    /// @notice Thrown when attempting to register a commitment that has already been registered.
    error REGISTERED_COMMITMENT();
    
    // ====================================================
    // Modifiers
    // ====================================================

    /**
     * @notice Modifier to restrict access to functions to only the hub.
     * @dev Reverts if the hub is not set or if the caller is not the hub.
     */
    modifier onlyHub() {
        if (address(_hub) == address(0)) revert HUB_NOT_SET();
        if (msg.sender != address(_hub)) revert ONLY_HUB_CAN_ACCESS();
        _;
    }

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
     * @notice Initializes the registry implementation.
     * @dev Sets the hub address and initializes the UUPS upgradeable feature.
     * @param _hub The address of the identity verification hub.
     */
    function initialize(
        address _hub
    ) 
        external
        initializer 
    {
        __ImplRoot_init();
        _hub = _hub;
        emit RegistryInitialized(_hub);
    }

    // ====================================================
    // External Functions - View & Checks
    // ====================================================

    /**
     * @notice Retrieves the hub address.
     * @return The current identity verification hub address.
     */
    function hub() 
        external
        virtual
        onlyProxy
        view 
        returns (address) 
    {
        return _hub;
    }

    /**
     * @notice Checks if a specific nullifier is registered for a given attestation.
     * @param attestationId The attestation identifier.
     * @param nullifier The nullifier to be checked.
     * @return True if the nullifier has been registered, false otherwise.
     */
    function nullifiers(
        bytes32 attestationId,
        uint256 nullifier
    ) 
        external
        virtual
        onlyProxy
        view 
        returns (bool) 
    {
        return _nullifiers[attestationId][nullifier];
    }

    /**
     * @notice Checks if a DSC key commitment is registered.
     * @param commitment The DSC key commitment.
     * @return True if the DSC key commitment is registered, false otherwise.
     */
    function isRegisteredDscKeyCommitment(
        uint256 commitment
    ) 
        external
        virtual
        onlyProxy
        view 
        returns (bool) 
    {
        return _isRegisteredDscKeyCommitment[commitment];
    }

    /**
     * @notice Retrieves the timestamp when a specific Merkle root was created.
     * @param root The Merkle tree root.
     * @return The timestamp corresponding to the given root.
     */
    function rootTimestamps(
        uint256 root
    ) 
        external
        virtual
        onlyProxy
        view 
        returns (uint256) 
    {
        return _rootTimestamps[root];
    }

    /**
     * @notice Checks if the identity commitment Merkle tree contains the provided root.
     * @param root The Merkle tree root.
     * @return True if the root exists, false otherwise.
     */
    function checkIdentityCommitmentRoot(
        uint256 root
    ) 
        external
        onlyProxy
        view 
        returns (bool) 
    {
        return _rootTimestamps[root] != 0;
    }

    /**
     * @notice Retrieves the number of identity commitments in the Merkle tree.
     * @return The size of the identity commitment Merkle tree.
     */
    function getIdentityCommitmentMerkleTreeSize() 
        external
        onlyProxy
        view 
        returns (uint256) 
    {
        return _identityCommitmentIMT.size;
    }

    /**
     * @notice Retrieves the current Merkle root of the identity commitments.
     * @return The current identity commitment Merkle root.
     */
    function getIdentityCommitmentMerkleRoot() 
        external
        onlyProxy
        view 
        returns (uint256) 
    {
        return _identityCommitmentIMT._root();
    }

    /**
     * @notice Retrieves the index of a specific identity commitment in the Merkle tree.
     * @param commitment The identity commitment to locate.
     * @return The index of the provided commitment within the Merkle tree.
     */
    function getIdentityCommitmentIndex(
        uint256 commitment
    ) 
        external
        onlyProxy
        view 
        returns (uint256) 
    {
        return _identityCommitmentIMT._indexOf(commitment);
    }

    /**
     * @notice Retrieves the current OFAC root.
     * @return The stored OFAC root.
     */
    function getOfacRoot() 
        external
        onlyProxy
        view 
        returns (uint256) 
    {
        return _ofacRoot;
    }

    /**
     * @notice Validates whether the provided OFAC root matches the stored value.
     * @param root The OFAC root to validate.
     * @return True if the provided root is equal to the stored OFAC root, false otherwise.
     */
    function checkOfacRoot(
        uint256 root
    ) 
        external
        onlyProxy
        view 
        returns (bool) 
    {
        return _ofacRoot == root;
    }

    /**
     * @notice Retrieves the current CSCA root.
     * @return The stored CSCA root.
     */
    function getCscaRoot() 
        external
        onlyProxy
        view 
        returns (uint256) 
    {
        return _cscaRoot;
    }

    /**
     * @notice Validates whether the provided CSCA root matches the stored value.
     * @param root The CSCA root to validate.
     * @return True if the provided root is equal to the stored CSCA root, false otherwise.
     */
    function checkCscaRoot(
        uint256 root
    ) 
        external
        onlyProxy
        view 
        returns (bool) 
    {
        return _cscaRoot == root;
    }

    /**
     * @notice Retrieves the current Merkle root of the DSC key commitments.
     * @return The current DSC key commitment Merkle root.
     */
    function getDscKeyCommitmentMerkleRoot() 
        external
        onlyProxy
        view 
        returns (uint256) 
    {
        return _dscKeyCommitmentIMT._root();
    }

    /**
     * @notice Validates whether the provided root matches the DSC key commitment Merkle root.
     * @param root The root to validate.
     * @return True if the roots match, false otherwise.
     */
    function checkDscKeyCommitmentMerkleRoot(
        uint256 root
    ) 
        external
        onlyProxy
        view 
        returns (bool) 
    {
        return _dscKeyCommitmentIMT._root() == root;
    }

    /**
     * @notice Retrieves the number of DSC key commitments in the Merkle tree.
     * @return The DSC key commitment Merkle tree size.
     */
    function getDscKeyCommitmentTreeSize() 
        external
        onlyProxy
        view 
        returns (uint256) 
    {
        return _dscKeyCommitmentIMT.size;
    }

    /**
     * @notice Retrieves the index of a specific DSC key commitment in the Merkle tree.
     * @param commitment The DSC key commitment to locate.
     * @return The index of the provided commitment within the DSC key commitment Merkle tree.
     */
    function getDscKeyCommitmentIndex(
        uint256 commitment
    )
        external
        onlyProxy
        view
        returns (uint256)
    {
        return _dscKeyCommitmentIMT._indexOf(commitment);
    }

    // ====================================================
    // External Functions - Registration & Updates
    // ====================================================

    /**
     * @notice Registers a new identity commitment.
     * @dev Caller must be the hub. Reverts if the nullifier is already registered.
     * @param attestationId The identifier for the attestation.
     * @param nullifier The nullifier associated with the identity commitment.
     * @param commitment The identity commitment to register.
     */
    function registerCommitment(
        bytes32 attestationId,
        uint256 nullifier,
        uint256 commitment
    ) 
        external
        onlyProxy
        onlyHub
    {
        if (_nullifiers[attestationId][nullifier]) revert REGISTERED_COMMITMENT();

        _nullifiers[attestationId][nullifier] = true;
        uint256 index = _identityCommitmentIMT.size;
        uint256 imt_root = _addCommitment(_identityCommitmentIMT, commitment);
        _rootTimestamps[imt_root] = block.timestamp;
        emit CommitmentRegistered(attestationId, nullifier, commitment, block.timestamp, imt_root, index);
    }

    /**
     * @notice Registers a new DSC key commitment.
     * @dev Caller must be the hub. Reverts if the commitment has already been registered.
     * @param dscCommitment The DSC key commitment to register.
     */
    function registerDscKeyCommitment(
        uint256 dscCommitment
    )
        external
        onlyProxy
        onlyHub
    {
        if (_isRegisteredDscKeyCommitment[dscCommitment]) revert REGISTERED_COMMITMENT();

        _isRegisteredDscKeyCommitment[dscCommitment] = true;
        uint256 index = _dscKeyCommitmentIMT.size;
        uint256 imt_root = _addCommitment(_dscKeyCommitmentIMT, dscCommitment);
        emit DscKeyCommitmentRegistered(dscCommitment, block.timestamp, imt_root, index);
    }
    
    /**
     * @notice Updates the hub address.
     * @dev Callable only via a proxy and restricted to the contract owner.
     * @param newHubAddress The new address of the hub.
     */
    function updateHub(
        address newHubAddress
    )
        external
        onlyProxy
        onlyOwner 
    { 
        _hub = newHubAddress;
        emit HubUpdated(newHubAddress);
    }

    /**
     * @notice Updates the OFAC root.
     * @dev Callable only via a proxy and restricted to the contract owner.
     * @param newOfacRoot The new OFAC root value.
     */
    function updateOfacRoot(
        uint256 newOfacRoot
    ) 
        external
        onlyProxy
        onlyOwner 
    {
        _ofacRoot = newOfacRoot;
        emit OfacRootUpdated(newOfacRoot);
    }

    /**
     * @notice Updates the CSCA root.
     * @dev Callable only via a proxy and restricted to the contract owner.
     * @param newCscaRoot The new CSCA root value.
     */
    function updateCscaRoot(
        uint256 newCscaRoot
    ) 
        external
        onlyProxy
        onlyOwner 
    {
        _cscaRoot = newCscaRoot;
        emit CscaRootUpdated(newCscaRoot);
    }

    // ====================================================
    // External Functions - Development Only
    // ====================================================

    /**
     * @notice (DEV) Force-adds an identity commitment.
     * @dev Callable only by the owner for testing or administration.
     * @param attestationId The identifier for the attestation.
     * @param nullifier The nullifier associated with the identity commitment.
     * @param commitment The identity commitment to add.
     */
    function devAddIdentityCommitment(
        bytes32 attestationId,
        uint256 nullifier,
        uint256 commitment
    ) 
        external 
        onlyProxy
        onlyOwner 
    {
        _nullifiers[attestationId][nullifier] = true;
        uint256 imt_root = _addCommitment(_identityCommitmentIMT, commitment);
        _rootTimestamps[imt_root] = block.timestamp;
        uint256 index = _identityCommitmentIMT._indexOf(commitment);
        emit DevCommitmentRegistered(attestationId, nullifier, commitment, block.timestamp, imt_root, index);
    }

    /**
     * @notice (DEV) Updates an existing identity commitment.
     * @dev Caller must be the owner. Provides sibling nodes for proof of position.
     * @param oldLeaf The current identity commitment to update.
     * @param newLeaf The new identity commitment.
     * @param siblingNodes An array of sibling nodes for Merkle proof generation.
     */
    function devUpdateCommitment(
        uint256 oldLeaf,
        uint256 newLeaf,
        uint256[] calldata siblingNodes
    )
        external
        onlyProxy
        onlyOwner
    {
        uint256 imt_root = _updateCommitment(_identityCommitmentIMT, oldLeaf, newLeaf, siblingNodes);
        _rootTimestamps[imt_root] = block.timestamp;
        emit DevCommitmentUpdated(oldLeaf, newLeaf, imt_root, block.timestamp);
    }

    /**
     * @notice (DEV) Removes an existing identity commitment.
     * @dev Caller must be the owner. Provides sibling nodes for proof of position.
     * @param oldLeaf The identity commitment to remove.
     * @param siblingNodes An array of sibling nodes for Merkle proof generation.
     */
    function devRemoveCommitment(
        uint256 oldLeaf,
        uint256[] calldata siblingNodes
    )
        external
        onlyProxy
        onlyOwner
    {
        uint256 imt_root = _removeCommitment(_identityCommitmentIMT, oldLeaf, siblingNodes);
        _rootTimestamps[imt_root] = block.timestamp;
        emit DevCommitmentRemoved(oldLeaf, imt_root, block.timestamp);
    }
    
    /**
     * @notice (DEV) Force-adds a DSC key commitment.
     * @dev Callable only by the owner for testing or administration.
     * @param dscCommitment The DSC key commitment to add.
     */
    function devAddDscKeyCommitment(
        uint256 dscCommitment
    )
        external
        onlyProxy
        onlyOwner
    {
        _isRegisteredDscKeyCommitment[dscCommitment] = true;
        uint256 imt_root = _addCommitment(_dscKeyCommitmentIMT, dscCommitment);
        uint256 index = _dscKeyCommitmentIMT._indexOf(dscCommitment);
        emit DevDscKeyCommitmentRegistered(dscCommitment, imt_root, index);
    }

    /**
     * @notice (DEV) Updates an existing DSC key commitment.
     * @dev Caller must be the owner. Provides sibling nodes for proof of position.
     * @param oldLeaf The current DSC key commitment to update.
     * @param newLeaf The new DSC key commitment.
     * @param siblingNodes An array of sibling nodes for Merkle proof generation.
     */
    function devUpdateDscKeyCommitment(
        uint256 oldLeaf,
        uint256 newLeaf,
        uint256[] calldata siblingNodes
    )
        external
        onlyProxy
        onlyOwner
    {
        uint256 imt_root = _updateCommitment(_dscKeyCommitmentIMT, oldLeaf, newLeaf, siblingNodes);
        emit DevDscKeyCommitmentUpdated(oldLeaf, newLeaf, imt_root);
    }

    /**
     * @notice (DEV) Removes an existing DSC key commitment.
     * @dev Caller must be the owner. Provides sibling nodes for proof of position.
     * @param oldLeaf The DSC key commitment to remove.
     * @param siblingNodes An array of sibling nodes for Merkle proof generation.
     */
    function devRemoveDscKeyCommitment(
        uint256 oldLeaf,
        uint256[] calldata siblingNodes
    )
        external
        onlyProxy
        onlyOwner
    {
        uint256 imt_root = _removeCommitment(_dscKeyCommitmentIMT, oldLeaf, siblingNodes);
        emit DevDscKeyCommitmentRemoved(oldLeaf, imt_root);
    }

    /**
     * @notice (DEV) Changes the state of a nullifier.
     * @dev Callable only by the owner.
     * @param attestationId The attestation identifier.
     * @param nullifier The nullifier whose state is to be updated.
     * @param state The new state of the nullifier (true for registered, false for not registered).
     */
    function devChangeNullifierState(
        bytes32 attestationId,
        uint256 nullifier,
        bool state
    ) 
        external
        onlyProxy
        onlyOwner
    {
        _nullifiers[attestationId][nullifier] = state;
        emit DevNullifierStateChanged(attestationId, nullifier, state);
    }

    /**
     * @notice (DEV) Changes the registration state of a DSC key commitment.
     * @dev Callable only by the owner.
     * @param dscCommitment The DSC key commitment.
     * @param state The new state of the DSC key commitment (true for registered, false for not registered).
     */
    function devChangeDscKeyCommitmentState(
        uint256 dscCommitment,
        bool state
    )
        external
        onlyProxy
        onlyOwner
    {
        _isRegisteredDscKeyCommitment[dscCommitment] = state;
        emit DevDscKeyCommitmentStateChanged(dscCommitment, state);
    }

    // ====================================================
    // Internal Functions
    // ====================================================

    /**
     * @notice Adds a commitment to the specified Merkle tree.
     * @dev Inserts the commitment using the provided Merkle tree structure.
     * @param imt The Merkle tree data structure.
     * @param commitment The commitment to add.
     * @return imt_root The new Merkle tree root after insertion.
     */
    function _addCommitment(
        LeanIMTData storage imt,
        uint256 commitment
    ) 
        internal
        returns(uint256 imt_root)
    {
        imt_root = imt._insert(commitment);
    }

    /**
     * @notice Updates an existing commitment in the specified Merkle tree.
     * @dev Uses sibling nodes to prove the commitment's position and update it.
     * @param imt The Merkle tree data structure.
     * @param oldLeaf The current commitment to update.
     * @param newLeaf The new commitment.
     * @param siblingNodes An array of sibling nodes for generating a valid proof.
     * @return imt_root The new Merkle tree root after update.
     */
    function _updateCommitment(
        LeanIMTData storage imt,
        uint256 oldLeaf,
        uint256 newLeaf,
        uint256[] calldata siblingNodes
    )
        internal
        returns(uint256 imt_root)
    {
        imt_root = imt._update(oldLeaf, newLeaf, siblingNodes);
    }

    /**
     * @notice Removes a commitment from the specified Merkle tree.
     * @dev Uses sibling nodes to prove the commitment's position before removal.
     * @param imt The Merkle tree data structure.
     * @param oldLeaf The commitment to remove.
     * @param siblingNodes An array of sibling nodes for generating a valid proof.
     * @return imt_root The new Merkle tree root after removal.
     */
    function _removeCommitment(
        LeanIMTData storage imt,
        uint256 oldLeaf,
        uint256[] calldata siblingNodes
    )
        internal
        returns(uint256 imt_root)
    {
        imt_root = imt._remove(oldLeaf, siblingNodes);
    }
}