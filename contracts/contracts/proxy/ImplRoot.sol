// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/access/Ownable2StepUpgradeable.sol";

abstract contract ImplRoot is UUPSUpgradeable, Ownable2StepUpgradeable {

    uint256[50] private __gap;
    
    function __ImplRoot_init() internal virtual onlyInitializing {
        __Ownable_init(msg.sender);
        __UUPSUpgradeable_init();
    }

    function _authorizeUpgrade(address newImplementation) 
        internal
        virtual 
        override
        onlyProxy
        onlyOwner 
    {}
}
