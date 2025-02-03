#!/bin/bash

# Common colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

download_ptau() {
    local POWEROFTAU=$1
    mkdir -p build
    cd build
    if [ ! -f powersOfTau28_hez_final_${POWEROFTAU}.ptau ]; then
        echo -e "${YELLOW}Download power of tau....${NC}"
        wget https://hermez.s3-eu-west-1.amazonaws.com/powersOfTau28_hez_final_${POWEROFTAU}.ptau
        echo -e "${GREEN}Finished download!${NC}"
    else 
        echo -e "${YELLOW}Powers of tau file already downloaded${NC}"
    fi
    cd ..
}

get_random_string() {
    if command -v openssl &> /dev/null; then
        echo $(openssl rand -hex 64)
    else
        echo $(date +%s)
    fi
}

build_circuit() {
    local CIRCUIT_NAME=$1
    local CIRCUIT_TYPE=$2
    local POWEROFTAU=$3
    local OUTPUT_DIR=$4
    local START_TIME=$(date +%s)

    echo -e "${BLUE}Compiling circuit: $CIRCUIT_NAME${NC}"
    
    # Create output directory
    mkdir -p ${OUTPUT_DIR}/${CIRCUIT_NAME}/
    
    # Set circuit path based on CIRCUIT_TYPE
    local CIRCUIT_PATH
    if [ "$CIRCUIT_TYPE" = "register" ] || [ "$CIRCUIT_TYPE" = "dsc" ]; then
        CIRCUIT_PATH="circuits/${CIRCUIT_TYPE}/instances/${CIRCUIT_NAME}.circom"
    else
        CIRCUIT_PATH="circuits/${CIRCUIT_TYPE}/${CIRCUIT_NAME}.circom"
    fi
    
    # Compile circuit
    circom ${CIRCUIT_PATH} \
        -l node_modules \
        -l ./node_modules/@zk-kit/binary-merkle-root.circom/src \
        -l ./node_modules/circomlib/circuits \
        --r1cs --O1 --wasm -c \
        --output ${OUTPUT_DIR}/${CIRCUIT_NAME}/

    echo -e "${BLUE}Building zkey${NC}"
    NODE_OPTIONS="--max-old-space-size=40960" yarn snarkjs groth16 setup \
        ${OUTPUT_DIR}/${CIRCUIT_NAME}/${CIRCUIT_NAME}.r1cs \
        build/powersOfTau28_hez_final_${POWEROFTAU}.ptau \
        ${OUTPUT_DIR}/${CIRCUIT_NAME}/${CIRCUIT_NAME}.zkey

    # Generate and contribute random string
    local RAND_STR=$(get_random_string)
    echo $RAND_STR | yarn snarkjs zkey contribute \
        ${OUTPUT_DIR}/${CIRCUIT_NAME}/${CIRCUIT_NAME}.zkey \
        ${OUTPUT_DIR}/${CIRCUIT_NAME}/${CIRCUIT_NAME}_final.zkey

    echo -e "${BLUE}Building vkey${NC}"
    yarn snarkjs zkey export verificationkey \
        ${OUTPUT_DIR}/${CIRCUIT_NAME}/${CIRCUIT_NAME}_final.zkey \
        ${OUTPUT_DIR}/${CIRCUIT_NAME}/${CIRCUIT_NAME}_vkey.json

    # Generate and copy Solidity verifier
    yarn snarkjs zkey export solidityverifier \
        ${OUTPUT_DIR}/${CIRCUIT_NAME}/${CIRCUIT_NAME}_final.zkey \
        ${OUTPUT_DIR}/${CIRCUIT_NAME}/Verifier_${CIRCUIT_NAME}.sol

    OS=""

    case "$(uname)" in
    'Darwin')
        OS='Mac'
        ;;
    'Linux')
        OS='Linux'
        ;;
    *)
        echo "Unsupported platform: $(uname -a)"
        exit 1
        ;;
    esac

    if [ "$OS" = 'Mac' ]; then
        sed -i '' "s/Groth16Verifier/Verifier_${CIRCUIT_NAME}/g" \
            ${OUTPUT_DIR}/${CIRCUIT_NAME}/Verifier_${CIRCUIT_NAME}.sol
    elif [ "$OS" = 'Linux' ]; then
        sed -i "s/Groth16Verifier/Verifier_${CIRCUIT_NAME}/g" \
            ${OUTPUT_DIR}/${CIRCUIT_NAME}/Verifier_${CIRCUIT_NAME}.sol
    fi

    # Copy verifier to contracts directory
    mkdir -p ../contracts/contracts/verifiers/local/${CIRCUIT_TYPE}/
    cp ${OUTPUT_DIR}/${CIRCUIT_NAME}/Verifier_${CIRCUIT_NAME}.sol \
        ../contracts/contracts/verifiers/local/${CIRCUIT_TYPE}/Verifier_${CIRCUIT_NAME}.sol
    
    echo -e "${BLUE}Copied Verifier_${CIRCUIT_NAME}.sol to contracts${NC}"

    # Print build statistics
    echo -e "${GREEN}Build of $CIRCUIT_NAME completed in $(($(date +%s) - START_TIME)) seconds${NC}"
    echo -e "${BLUE}Size of ${CIRCUIT_NAME}.r1cs: $(wc -c < ${OUTPUT_DIR}/${CIRCUIT_NAME}/${CIRCUIT_NAME}.r1cs) bytes${NC}"
    echo -e "${BLUE}Size of ${CIRCUIT_NAME}.wasm: $(wc -c < ${OUTPUT_DIR}/${CIRCUIT_NAME}/${CIRCUIT_NAME}_js/${CIRCUIT_NAME}.wasm) bytes${NC}"
    echo -e "${BLUE}Size of ${CIRCUIT_NAME}_final.zkey: $(wc -c < ${OUTPUT_DIR}/${CIRCUIT_NAME}/${CIRCUIT_NAME}_final.zkey) bytes${NC}"
}

build_circuits() {
    local CIRCUITS=("$@")
    local CIRCUIT_TYPE="$1"
    local OUTPUT_DIR="$2"
    shift 2 
    local TOTAL_START_TIME=$(date +%s)

    # Build circuits
    for circuit in "${CIRCUITS[@]}"; do
        IFS=':' read -r CIRCUIT_NAME POWEROFTAU BUILD_FLAG <<< "$circuit"
        if [ "$BUILD_FLAG" = "true" ]; then
            # Download ptau file
            IFS=':' read -r _ POWEROFTAU _ <<< "$circuit"
            download_ptau $POWEROFTAU
            # Build circuit
            echo -e "${BLUE}Building circuit $CIRCUIT_NAME${NC}"
            build_circuit "$CIRCUIT_NAME" "$CIRCUIT_TYPE" "$POWEROFTAU" "$OUTPUT_DIR"
        else
            echo -e "${GRAY}Skipping build for $CIRCUIT_NAME${NC}"
        fi
    done

    echo -e "${GREEN}Total completed in $(($(date +%s) - TOTAL_START_TIME)) seconds${NC}"
}