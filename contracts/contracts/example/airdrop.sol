// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {IERC20, SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {MerkleProof} from "@openzeppelin/contracts/utils/cryptography/MerkleProof.sol";
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {IIdentityVerificationHubV1} from "../interfaces/IIdentityVerificationHubV1.sol";
import {IVcAndDiscloseCircuitVerifier} from "../interfaces/IVcAndDiscloseCircuitVerifier.sol";

contract Airdrop is Ownable {
    using SafeERC20 for IERC20;

    IERC20 public immutable token;
    bytes32 public merkleRoot;

    uint256 public immutable scope;
    uint256 public immutable attestationId;

    bool public registrationOpen;

    IIdentityVerificationHubV1 public immutable identityVerificationHub;

    mapping(address => bool) public elligibleAddresses;
    mapping(uint256 => address) public nullifiers;

    mapping(address => uint256) public claimableAmount;

    mapping(address => bool) public claimed;

    error InvalidProof();
    error InvalidScope();
    error InvalidAttestationId();
    error AlreadyRegistered(uint256 nullifier);
    error RegistrationClosed();
    error InvalidLength();
    error AlreadyClaimed();

    event Claimed(uint256 index, address account, uint256 amount);

    constructor(address _token, uint256 _scope, uint256 _attestationId, address _identityVerificationHub) Ownable(msg.sender) {
        token = IERC20(_token);
        scope = _scope;
        identityVerificationHub = IIdentityVerificationHubV1(_identityVerificationHub);
        attestationId = _attestationId;
    }

    function setMerkleRoot(bytes32 _merkleRoot) external onlyOwner {
        merkleRoot = _merkleRoot;
    }

    function openRegistration() external onlyOwner {
        registrationOpen = true;
    }

    function closeRegistration() external onlyOwner {
        registrationOpen = false;
    }

    function setClaimableAmount(address _address, uint256 _amount) external onlyOwner {
        claimableAmount[_address] = _amount;
    }

    function setBatchClaimableAmount(address[] memory _addresses, uint256[] memory _amounts) external onlyOwner {
        if (_addresses.length != _amounts.length) {
            revert InvalidLength();
        }
        for (uint256 i = 0; i < _addresses.length; i++) {
            claimableAmount[_addresses[i]] = _amounts[i];
        }
    }

    function verifyAndRegister(
        IVcAndDiscloseCircuitVerifier.VcAndDiscloseProof memory proof
    ) external {
        if (!registrationOpen) {
            revert RegistrationClosed();
        }

        IIdentityVerificationHubV1.VcAndDiscloseVerificationResult memory result = identityVerificationHub.verifyVcAndDiscloseAndGetResult(proof);

        if (result.scope != scope) {
            revert InvalidScope();
        }

        if (nullifiers[result.nullifier] != address(0)) {
            revert AlreadyRegistered(result.nullifier);
        }

        if (result.attestationId != attestationId) {
            revert InvalidAttestationId();
        }

        nullifiers[result.nullifier] = msg.sender;

        elligibleAddresses[msg.sender] = true;
    }

    function claim(
        uint256 index,
        uint256 amount,
        bytes32[] memory merkleProof
    ) external {
        if (claimed[msg.sender]) {
            revert AlreadyClaimed();
        }

        // Verify the merkle proof.
        bytes32 node = keccak256(abi.encodePacked(index, msg.sender, amount));
        if (!MerkleProof.verify(merkleProof, merkleRoot, node)) revert InvalidProof();

        // Mark it claimed and send the token.
        _setClaimed(index);
        IERC20(token).safeTransfer(msg.sender, amount);

        emit Claimed(index, msg.sender, amount);
    }

    function _setClaimed(uint256 index) internal {
        claimed[msg.sender] = true;
    }

}
