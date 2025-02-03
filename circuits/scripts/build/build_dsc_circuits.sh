#!/bin/bash

source "scripts/build/common.sh"

# Circuit-specific configurations
CIRCUIT_TYPE="dsc"
OUTPUT_DIR="build/${CIRCUIT_TYPE}"

# Define circuits and their configurations
# format: name:poweroftau:build_flag
CIRCUITS=(
    # ECDSA circuits
    "dsc_sha1_ecdsa_brainpoolP256r1:21:false"
    "dsc_sha256_ecdsa_brainpoolP224r1:21:false"
    "dsc_sha256_ecdsa_brainpoolP256r1:21:false"
    "dsc_sha256_ecdsa_brainpoolP384r1:21:false"
    "dsc_sha256_ecdsa_secp256r1:21:false"
    "dsc_sha256_ecdsa_secp384r1:21:false"
    "dsc_sha256_ecdsa_secp521r1:21:false"
    "dsc_sha384_ecdsa_brainpoolP384r1:21:false"
    "dsc_sha384_ecdsa_brainpoolP512r1:21:false"
    "dsc_sha384_ecdsa_secp384r1:21:false"
    "dsc_sha512_ecdsa_brainpoolP512r1:21:false"
    "dsc_sha512_ecdsa_secp521r1:21:false"

    # RSA circuits
    "dsc_sha1_rsa_65537_4096:21:false"
    "dsc_sha256_rsa_65537_4096:21:true"
    "dsc_sha512_rsa_65537_4096:21:false"

    # RSA-PSS circuits
    "dsc_sha256_rsapss_3_32_3072:22:false"
    "dsc_sha256_rsapss_65537_32_3072:22:false"
    "dsc_sha256_rsapss_65537_32_4096:22:false"
    "dsc_sha512_rsapss_65537_64_4096:22:false"
)

build_circuits "$CIRCUIT_TYPE" "$OUTPUT_DIR" "${CIRCUITS[@]}" 