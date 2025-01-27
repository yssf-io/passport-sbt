// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/access/Ownable2StepUpgradeable.sol";
import "@openzeppelin/contracts/utils/Strings.sol";
import "@zk-kit/imt.sol/internal/InternalLeanIMT.sol";
import "../interfaces/IIdentityRegistryV1.sol";
import "../interfaces/IIdentityVerificationHubV1.sol";
import "../proxy/ImplRoot.sol";
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
abstract contract IdentityRegistryStorageV1 is
    ImplRoot
{
    address internal _hub;

    // CSCA root
    uint256 internal _cscaRoot;

    // commitment registry
    LeanIMTData internal _identityCommitmentIMT;
    // timestamp of when the root was created
    mapping(uint256 => uint256) internal _rootTimestamps;
    // attestation id => nullifier => bool
    // attestation id for each identity type
    // passport: 0x12d57183e0a41615471a14e5a93c87b9db757118c1d7a6a9f73106819d656f24
    // poseidon("E-PASSPORT")
    mapping(bytes32 => mapping(uint256 => bool)) internal _nullifiers;

    // ofac registry
    uint256 internal _ofacRoot;
}

contract IdentityRegistryImplV1 is 
    IdentityRegistryStorageV1,  
    IIdentityRegistryV1 
{

    // using Strings for uint256;
    using InternalLeanIMT for LeanIMTData;

    // Events
    event RegistryInitialized(address hub);
    event HubUpdated(address hub);
    event CscaRootUpdated(uint256 cscaRoot);
    event OfacRootUpdated(uint256 ofacRoot);
    event CommitmentRegistered(bytes32 indexed attestationId, uint256 indexed nullifier, uint256 indexed commitment, uint256 timestamp, uint256 imtRoot, uint256 imtIndex);
    event DevCommitmentRegistered(bytes32 indexed attestationId, uint256 indexed nullifier, uint256 indexed commitment, uint256 timestamp, uint256 imtRoot, uint256 imtIndex);
    event DevCommitmentUpdated(uint256 indexed oldLeaf, uint256 indexed newLeaf, uint256 imtRoot, uint256 timestamp);
    event DevCommitmentRemoved(uint256 indexed oldLeaf, uint256 imtRoot, uint256 timestamp);
    event DevNullifierRemoved(bytes32 indexed attestationId, uint256 indexed nullifier, uint256 timestamp);

    // Errors
    error HUB_NOT_SET();
    error ONLY_HUB_CAN_REGISTER_COMMITMENT();
    error REGISTERED_IDENTITY();

    // Constructor
    constructor() {
        _disableInitializers();
    }
    
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

    ///////////////////////////////////////////////////////////////////
    ///                     EXTERNAL FUNCTIONS                      ///
    ///////////////////////////////////////////////////////////////////

    // view
    function hub() 
        external
        virtual
        onlyProxy
        view 
        returns (address) 
    {
        return _hub;
    }

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

    function getIdentityCommitmentMerkleTreeSize() 
        external
        onlyProxy
        view 
        returns (uint256) 
    {
        return _identityCommitmentIMT.size;
    }

    function getIdentityCommitmentMerkleRoot() 
        external
        onlyProxy
        view 
        returns (uint256) 
    {
        return _identityCommitmentIMT._root();
    }

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

    function getOfacRoot() 
        external
        onlyProxy
        view 
        returns (uint256) 
    {
        return _ofacRoot;
    }

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

    function getCscaRoot() 
        external
        onlyProxy
        view 
        returns (uint256) 
    {
        return _cscaRoot;
    }

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

    // register
    function registerCommitment(
        bytes32 attestationId,
        uint256 nullifier,
        uint256 commitment
    ) 
        external
        onlyProxy
    {
        if (address(_hub) == address(0)) revert HUB_NOT_SET();
        if (msg.sender != address(_hub)) revert ONLY_HUB_CAN_REGISTER_COMMITMENT();
        if (_nullifiers[attestationId][nullifier]) revert REGISTERED_IDENTITY();

        _nullifiers[attestationId][nullifier] = true;
        uint256 index = _identityCommitmentIMT.size;
        uint256 imt_root = _addCommitment(commitment);
        emit CommitmentRegistered(attestationId, nullifier, commitment, block.timestamp, imt_root, index);
    }
    
    // onlyOwner
    function updateHub(
        address hub
    )
        external
        onlyProxy
        onlyOwner 
    { 
        _hub = hub;
        emit HubUpdated(hub);
    }

    function updateOfacRoot(
        uint256 ofacRoot
    ) 
        external
        onlyProxy
        onlyOwner 
    {
        _ofacRoot = ofacRoot;
        emit OfacRootUpdated(ofacRoot);
    }

    function updateCscaRoot(
        uint256 cscaRoot
    ) 
        external
        onlyProxy
        onlyOwner 
    {
        _cscaRoot = cscaRoot;
        emit CscaRootUpdated(cscaRoot);
    }

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
        uint256 imt_root = _addCommitment(commitment);
        uint256 index = _identityCommitmentIMT._indexOf(commitment);
        emit DevCommitmentRegistered(attestationId, nullifier, commitment, block.timestamp, imt_root, index);
    }

    function devUpdateCommitment(
        uint256 oldLeaf,
        uint256 newLeaf,
        uint256[] calldata siblingNodes
    )
        external
        onlyProxy
        onlyOwner
    {
        uint256 imt_root = _updateCommitment(oldLeaf, newLeaf, siblingNodes);
        emit DevCommitmentUpdated(oldLeaf, newLeaf, imt_root, block.timestamp);
    }

    function devRemoveCommitment(
        uint256 oldLeaf,
        uint256[] calldata siblingNodes
    )
        external
        onlyProxy
        onlyOwner
    {
        uint256 imt_root = _removeCommitment(oldLeaf, siblingNodes);
        emit DevCommitmentRemoved(oldLeaf, imt_root, block.timestamp);
    }

    function devRemoveNullifier(
        bytes32 attestationId,
        uint256 nullifier
    )
        external
        onlyProxy
        onlyOwner
    {
        _nullifiers[attestationId][nullifier] = false;
        emit DevNullifierRemoved(attestationId, nullifier, block.timestamp);
    }

    ///////////////////////////////////////////////////////////////////
    ///                     INTERNAL FUNCTIONS                      ///
    ///////////////////////////////////////////////////////////////////
    
    function _addCommitment(
        uint256 commitment
    ) 
        internal
        returns(uint256 imt_root)
    {
        imt_root = _identityCommitmentIMT._insert(commitment);
        _rootTimestamps[imt_root] = block.timestamp;
    }

    function _updateCommitment(
        uint256 oldLeaf,
        uint256 newLeaf,
        uint256[] calldata siblingNodes
    )
        internal
        returns(uint256 imt_root)
    {
        imt_root = _identityCommitmentIMT._update(oldLeaf, newLeaf, siblingNodes);
        _rootTimestamps[imt_root] = block.timestamp;
    }

    function _removeCommitment(
        uint256 oldLeaf,
        uint256[] calldata siblingNodes
    )
        internal
        returns(uint256 imt_root)
    {
        imt_root = _identityCommitmentIMT._remove(oldLeaf, siblingNodes);
        _rootTimestamps[imt_root] = block.timestamp;
    }
}