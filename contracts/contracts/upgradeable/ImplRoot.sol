// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/access/Ownable2StepUpgradeable.sol";

/**
 * @title ImplRoot
 * @dev Abstract contract providing upgradeable functionality via UUPSUpgradeable,
 * along with a two-step ownable mechanism using Ownable2StepUpgradeable.
 * Serves as a base for upgradeable implementations.
 */
abstract contract ImplRoot is UUPSUpgradeable, Ownable2StepUpgradeable {

    // Reserved storage space to allow for layout changes in the future.
    uint256[50] private __gap;
    
    /**
     * @dev Initializes the contract by setting the deployer as the initial owner and initializing
     * the UUPS proxy functionality.
     *
     * This function should be called in the initializer of the derived contract.
     */
    function __ImplRoot_init() internal virtual onlyInitializing {
        __Ownable_init(msg.sender);
        __UUPSUpgradeable_init();
    }

    /**
     * @dev Authorizes an upgrade to a new implementation. 
     * Requirements:
     *   - Must be called through a proxy.
     *   - Caller must be the contract owner.
     *
     * @param newImplementation The address of the new implementation contract.
     */
    function _authorizeUpgrade(address newImplementation)
        internal
        virtual
        override
        onlyProxy
        onlyOwner 
    {}
}
