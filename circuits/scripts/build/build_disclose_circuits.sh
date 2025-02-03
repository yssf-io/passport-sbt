#!/bin/bash

source "scripts/build/common.sh"

# Circuit-specific configurations
CIRCUIT_TYPE="disclose"
OUTPUT_DIR="build/${CIRCUIT_TYPE}"

# Define circuits and their configurations
# format: name:poweroftau:build_flag
CIRCUITS=(
    "vc_and_disclose:20:true"
)

build_circuits "$CIRCUIT_TYPE" "$OUTPUT_DIR" "${CIRCUITS[@]}" 