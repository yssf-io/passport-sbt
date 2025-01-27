// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import "./IRegisterCircuitVerifier.sol";
import "./IDscCircuitVerifier.sol";
import "./IVcAndDiscloseCircuitVerifier.sol";
interface IIdentityVerificationHubV1 {

    struct VcAndDiscloseVerificationResult {
        uint256 attestationId;
        uint256 scope;
        uint256 userIdentifier;
        uint256 nullifier;
        uint256[3] revealedDataPacked;
        uint256 forbiddenCountriesListPacked;
    }

    struct PassportProof {
        uint256 registerCircuitVerifierId;
        uint256 dscCircuitVerifierId;
        IRegisterCircuitVerifier.RegisterCircuitProof registerCircuitProof;
        IDscCircuitVerifier.DscCircuitProof dscCircuitProof;
    }

    function verifyVcAndDiscloseAndGetResult(
        IVcAndDiscloseCircuitVerifier.VcAndDiscloseProof memory proof
    )
        external
        view
        returns (VcAndDiscloseVerificationResult memory);

} 