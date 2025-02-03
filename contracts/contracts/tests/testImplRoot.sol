// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import "../../contracts/upgradeable/ImplRoot.sol";

contract MockImplRoot is ImplRoot {

    function exposed__ImplRoot_init() external {
        __ImplRoot_init();
    }

    function exposed__Ownable_init(address initialOwner) external initializer() {
        __Ownable_init(initialOwner);
    }

    function exposed_authorizeUpgrade(address newImplementation) external {
        _authorizeUpgrade(newImplementation);
    }
}