// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import "./proxy/ProxyRoot.sol";

contract IdentityVerificationHub is ProxyRoot {
    constructor(address _logic, bytes memory _data) ProxyRoot(_logic, _data) {}
}