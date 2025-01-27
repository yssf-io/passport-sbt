#!/bin/bash

source "scripts/build/common.sh"

# Circuit-specific configurations
CIRCUIT_TYPE="dsc"
OUTPUT_DIR="build/${CIRCUIT_TYPE}"

# Define circuits and their configurations
# format: name:poweroftau:build_flag
CIRCUITS=(
    "dsc_rsa_sha1_65537_4096:21:false"
    "dsc_rsa_sha256_65537_4096:21:true"
    "dsc_rsapss_sha256_65537_4096:22:false"
)

build_circuits "$CIRCUIT_TYPE" "$OUTPUT_DIR" "${CIRCUITS[@]}" 