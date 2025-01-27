import { Signer } from "ethers";
import { PassportData } from "../../../common/src/utils/types";

import type { 
    PublicSignals,
    Groth16Proof
} from "snarkjs";

// Contract imports
import {
    IdentityVerificationHub,
    IdentityVerificationHubImplV1,
    IdentityRegistry,
    IdentityRegistryImplV1,
} from "../../typechain-types";

import type { 
    IIdentityVerificationHubV1,
    IRegisterCircuitVerifier,
    IDscCircuitVerifier,
    IVcAndDiscloseCircuitVerifier
} from "../../typechain-types/contracts/IdentityVerificationHubImplV1";

export type PassportProof = IIdentityVerificationHubV1.PassportProofStruct;
export type RegisterCircuitProof = IRegisterCircuitVerifier.RegisterCircuitProofStruct;
export type DscCircuitProof = IDscCircuitVerifier.DscCircuitProofStruct;
export type VcAndDiscloseHubProof = IIdentityVerificationHubV1.VcAndDiscloseHubProofStruct;
export type VcAndDiscloseProof = IVcAndDiscloseCircuitVerifier.VcAndDiscloseProofStruct;

// Verifier type imports
import type { Verifier_vc_and_disclose as ProdVerifier } from "../../typechain-types/contracts/verifiers/disclose/Verifier_vc_and_disclose";
import type { Verifier_vc_and_disclose as LocalVerifier } from "../../typechain-types/contracts/verifiers/local/disclose/Verifier_vc_and_disclose";
import type { Verifier_register_rsa_65537_sha256_sha256_sha256_rsa_65537_4096 as ProdRegisterVerifier } from "../../typechain-types/contracts/verifiers/register/Verifier_register_rsa_65537_sha256_sha256_sha256_rsa_65537_4096";
import type { Verifier_register_sha256_sha256_sha256_rsa_65537_4096 as LocalRegisterVerifier } from "../../typechain-types/contracts/verifiers/local/register/Verifier_register_sha256_sha256_sha256_rsa_65537_4096";
import type { Verifier_dsc_rsa_65537_sha256_4096 as ProdDscVerifier } from "../../typechain-types/contracts/verifiers/dsc/Verifier_dsc_rsa_65537_sha256_4096";
import type { Verifier_dsc_rsa_sha256_65537_4096 as LocalDscVerifier } from "../../typechain-types/contracts/verifiers/local/dsc/Verifier_dsc_rsa_sha256_65537_4096";

// Type definitions
export type VcAndDiscloseVerifier = typeof process.env.TEST_ENV extends "local" ? LocalVerifier : ProdVerifier;
export type RegisterVerifier = typeof process.env.TEST_ENV extends "local" ? LocalRegisterVerifier : ProdRegisterVerifier;
export type DscVerifier = typeof process.env.TEST_ENV extends "local" ? LocalDscVerifier : ProdDscVerifier;

export interface DeployedActors {
    hub: IdentityVerificationHubImplV1;
    hubImpl: IdentityVerificationHubImplV1;
    registry: IdentityRegistryImplV1;
    registryImpl: IdentityRegistryImplV1;
    vcAndDisclose: VcAndDiscloseVerifier;
    register: RegisterVerifier;
    dsc: DscVerifier;
    owner: Signer;
    user1: Signer;
    mockPassport: PassportData;
}

// Contract type exports
export type {
    IdentityVerificationHub,
    IdentityVerificationHubImplV1,
    IdentityRegistry,
    IdentityRegistryImplV1,
    Groth16Proof,
    PublicSignals
};

export type CircuitArtifacts = {
    [key: string]: {
        wasm: string,
        zkey: string,
        vkey: string,
        verifier?: any,
        inputs?: any,
        parsedCallData?: any,
        formattedCallData?: any,
    }
}