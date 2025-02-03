#!/bin/bash

# Usage:
#   generate_certificate <role> <hash> <sig_alg> [<salt_if_rsapss>] <exp_or_curve> [<bits>] [--signer <csca_folder>] [--force]
#
#     <role> : "csca" or "dsc"
#     <hash> : "sha1", "sha256", "sha384", "sha512"
#     <sig_alg> : "rsa", "rsapss", "ecdsa"
#     [<salt_if_rsapss>] : only if sig_alg == "rsapss" (optional in this snippet; adapt if needed)
#     <exp_or_curve> : exponent if RSA/RSAPSS, curve name if ECDSA
#     <bits> : number of bits if RSA/RSAPSS
#
#   If <role>="csca", creates a self-signed root cert in "src/mock_certificates/<dir>"
#     with "mock_csca.key" & "mock_csca.pem"
#   If <role>="dsc", creates "src/mock_certificates/<dir>"
#     with "mock_dsc.key" & "mock_dsc.pem", signed by the CSCA in --signer <csca_folder>.
#
#   If the folder & files exist, we skip unless --force is specified.
#
# Example calls:
#   # Create a CSCA in folder "src/mock_certificates/sha256_rsa_65537_4096"
#   generate_certificate csca sha256 rsa 65537 4096
#
#   # Create a DSC in folder "src/mock_certificates/sha1_rsa_65537_2048" => mock_dsc.key/pem,
#   # signed by the just-created CSCA in folder "src/mock_certificates/sha256_rsa_65537_4096":
#   generate_certificate dsc sha1 rsa 65537 2048 --signer sha256_rsa_65537_4096

generate_certificate() {
    local role="$1"
    local hash="$2"
    local sig_alg="$3"

    shift 3

    local force_regen=false
    local signer=""

    # Optionally handle an RSAPSS salt. e.g.:
    #  generate_certificate csca sha256 rsapss 32 65537 4096
    local salt=""
    local exp_or_curve=""
    local bits=""

    # Collect (remaining) positional arguments, then parse flags.
    declare -a positional=()
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --signer)
                signer="$2"
                shift 2
                ;;
            --force)
                force_regen=true
                shift
                ;;
            *)
                positional+=("$1")
                shift
                ;;
        esac
    done

    # Convert the positional array back into $1, $2, ...
    set -- "${positional[@]}"

    # Build directory name:
    # - ECDSA =>     <hash>_<sig_alg>_<curve>
    # - RSAPSS =>    <hash>_<sig_alg>_<salt>_<exp>_<bits>
    # - RSA =>       <hash>_<sig_alg>_<exp>_<bits>
    #
    # Then prepend "src/mock_certificates/"

    local base_dir="src/mock_certificates"

    if [ "$sig_alg" = "ecdsa" ]; then
        exp_or_curve="$1"
        dir_name="${hash}_${sig_alg}_${exp_or_curve}"
    elif [ "$sig_alg" = "rsapss" ]; then
        salt="$1"
        exp_or_curve="$2"
        bits="$3"
        dir_name="${hash}_${sig_alg}_${salt}_${exp_or_curve}_${bits}"
    else
        exp_or_curve="$1"
        bits="$2"
        dir_name="${hash}_${sig_alg}_${exp_or_curve}_${bits}"
    fi

    dir_name="${base_dir}/${dir_name}"
    echo -e "\033[90m=== ROLE: $role, DIR: $dir_name\033[0m"

    # Filenames inside the directory
    local key_file="mock_csca.key"
    local crt_file="mock_csca.pem"
    [ "$role" = "dsc" ] && key_file="mock_dsc.key" && crt_file="mock_dsc.pem"

    mkdir -p "$dir_name"

    # If not forced, skip if they exist
    if $force_regen; then
        echo "[INFO] --force => removing old files in $dir_name"
        rm -f "$dir_name/$key_file" "$dir_name/$crt_file"
    else
        if [ -f "$dir_name/$key_file" ] && [ -f "$dir_name/$crt_file" ]; then
            echo -e "\033[90m[SKIP] $dir_name: $key_file and $crt_file exist (use --force to regenerate).\033[0m"
            return
        fi
    fi

    if [ "$role" = "csca" ]; then
        # Generate a self-signed CSCA
        if [ "$sig_alg" = "ecdsa" ]; then
            openssl ecparam -name "$exp_or_curve" -genkey -noout -out "$dir_name/$key_file"
            openssl req -new -x509 \
                -key "$dir_name/$key_file" \
                -out "$dir_name/$crt_file" \
                -days 3650 -sha${hash#sha} \
                -subj "/C=FR/ST=IDF/L=Paris/O=Mock CSCA/OU=PKI/CN=MockCSCA"
        elif [ "$sig_alg" = "rsapss" ]; then
            openssl genpkey -algorithm RSA-PSS \
                -pkeyopt rsa_keygen_bits:"$bits" \
                -pkeyopt rsa_keygen_pubexp:"$exp_or_curve" \
                -out "$dir_name/$key_file"
            openssl req -new -x509 \
                -key "$dir_name/$key_file" \
                -out "$dir_name/$crt_file" \
                -days 3650 -sha${hash#sha} \
                -sigopt rsa_padding_mode:pss \
                -sigopt rsa_pss_saltlen:"$salt" \
                -subj "/C=FR/ST=IDF/L=Paris/O=Mock CSCA/OU=PKI/CN=MockCSCA"
        else
            # Regular RSA
            openssl genpkey -algorithm RSA \
                -pkeyopt rsa_keygen_bits:"$bits" \
                -pkeyopt rsa_keygen_pubexp:"$exp_or_curve" \
                -out "$dir_name/$key_file"
            openssl req -new -x509 \
                -key "$dir_name/$key_file" \
                -out "$dir_name/$crt_file" \
                -days 3650 -sha${hash#sha} \
                -subj "/C=FR/ST=IDF/L=Paris/O=Mock CSCA/OU=PKI/CN=MockCSCA"
        fi
        echo "[OK] Created CSCA in $dir_name => $key_file, $crt_file"

    elif [ "$role" = "dsc" ]; then
        # We need --signer <csca_directory>
        if [ -z "$signer" ]; then
            echo -e "\033[31m[ERROR] Role 'dsc' requires --signer <csca_directory>.\033[0m"
            exit 1
        fi

        # If the user passed a bare folder name (without "src/mock_certificates/"), prepend it.
        if [[ "$signer" != src/mock_certificates/* ]]; then
            signer="src/mock_certificates/$signer"
        fi

        local csca_key="$signer/mock_csca.key"
        local csca_crt="$signer/mock_csca.pem"

        if [ ! -f "$csca_key" ] || [ ! -f "$csca_crt" ]; then
            echo "[ERROR] Could not find the signer's key/cert: $csca_key or $csca_crt"
            exit 1
        fi

        # Generate DSC key
        if [ "$sig_alg" = "ecdsa" ]; then
            openssl ecparam -name "$exp_or_curve" -genkey -noout -out "$dir_name/$key_file"
        elif [ "$sig_alg" = "rsapss" ]; then
            openssl genpkey -algorithm RSA-PSS \
                -pkeyopt rsa_keygen_bits:"$bits" \
                -pkeyopt rsa_keygen_pubexp:"$exp_or_curve" \
                -out "$dir_name/$key_file"
        else
            # RSA
            openssl genpkey -algorithm RSA \
                -pkeyopt rsa_keygen_bits:"$bits" \
                -pkeyopt rsa_keygen_pubexp:"$exp_or_curve" \
                -out "$dir_name/$key_file"
        fi

        # Create a CSR
        local csr_file="$dir_name/mocked_dsc.csr"
        openssl req -new \
            -key "$dir_name/$key_file" \
            -out "$csr_file" \
            -subj "/C=FR/ST=IDF/L=Paris/O=Mock DSC/OU=PKI/CN=MockDSC"

        # Sign with the CSCA
        openssl x509 -req -in "$csr_file" \
            -CA "$csca_crt" -CAkey "$csca_key" -CAcreateserial \
            -days 3650 -sha${hash#sha} \
            -out "$dir_name/$crt_file"

        # Clean up
        rm -f "$csr_file" "$signer/mock_csca.srl"
        echo "[OK] Created DSC in $dir_name => $key_file, $crt_file (signed by $signer)"

    else
        echo "[ERROR] Invalid role: $role (must be 'csca' or 'dsc')."
        exit 1
    fi

    echo ""
}

# ------------------------------------------------------------------------------
# Example usage:
#   # 1) Generate a CSCA in "src/mock_certificates/sha256_rsapss_32_65537_4096"
#   # => mock_csca.key/mem
#   generate_certificate csca sha256 rsapss 32 65537 4096
#
#   # 2) Generate a DSC in "src/mock_certificates/sha1_rsapss_32_65537_2048"
#   # => mock_dsc.key/mem
#   #    signed by the above CSCA folder
#   generate_certificate dsc sha1 rsapss 32 65537 2048 --signer sha256_rsapss_32_65537_4096
#
#   # Force re-gen if needed:
#   # generate_certificate csca sha256 rsapss 32 65537 4096 --force
#
#   # For ECDSA example:
#   # generate_certificate csca sha256 ecdsa secp256r1
#   # generate_certificate dsc sha1 ecdsa secp256r1 --signer sha256_ecdsa_secp256r1
#
#   # For RSA example:
#   # generate_certificate csca sha256 rsa 65537 4096
#   # generate_certificate dsc sha1 rsa 65537 2048 --signer sha256_rsa_65537_4096
# ------------------------------------------------------------------------------
# RSA certificates
generate_certificate csca sha1 rsa 65537 4096
generate_certificate dsc sha1 rsa 65537 2048 --signer sha1_rsa_65537_4096
generate_certificate dsc sha1 rsa 65537 4096 --signer sha1_rsa_65537_4096
generate_certificate csca sha256 rsa 65537 4096
generate_certificate dsc sha256 rsa 65537 2048 --signer sha256_rsa_65537_4096
generate_certificate dsc sha256 rsa 65537 3072 --signer sha256_rsa_65537_4096
generate_certificate dsc sha256 rsa 65537 4096 --signer sha256_rsa_65537_4096
generate_certificate csca sha384 rsa 65537 4096
generate_certificate dsc sha384 rsa 65537 4096 --signer sha384_rsa_65537_4096
generate_certificate csca sha512 rsa 65537 4096
generate_certificate dsc sha512 rsa 65537 2048 --signer sha512_rsa_65537_4096
generate_certificate dsc sha512 rsa 65537 4096 --signer sha512_rsa_65537_4096
generate_certificate csca sha256 rsa 3 4096
generate_certificate csca sha1 rsa 3 4096
generate_certificate dsc sha1 rsa 3 4096 --signer sha1_rsa_3_4096
generate_certificate dsc sha256 rsa 3 2048 --signer sha256_rsa_3_4096
generate_certificate dsc sha256 rsa 3 4096 --signer sha256_rsa_3_4096

# RSA-PSS certificates
generate_certificate csca sha256 rsapss 32 65537 4096
generate_certificate csca sha256 rsapss 32 65537 2048
generate_certificate csca sha256 rsapss 32 65537 3072
generate_certificate dsc sha256 rsapss 32 65537 4096 --signer sha256_rsapss_32_65537_4096
generate_certificate dsc sha256 rsapss 32 65537 2048 --signer sha256_rsapss_32_65537_2048
generate_certificate dsc sha256 rsapss 32 65537 3072 --signer sha256_rsapss_32_65537_3072
generate_certificate csca sha256 rsapss 32 3 4096
generate_certificate csca sha256 rsapss 32 3 3072
generate_certificate dsc sha256 rsapss 32 3 2048 --signer sha256_rsapss_32_3_4096
generate_certificate dsc sha256 rsapss 32 3 3072 --signer sha256_rsapss_32_3_3072
generate_certificate dsc sha256 rsapss 32 3 4096 --signer sha256_rsapss_32_3_4096
generate_certificate csca sha384 rsapss 48 65537 4096
generate_certificate csca sha384 rsapss 48 65537 3072
generate_certificate dsc sha384 rsapss 48 65537 2048 --signer sha384_rsapss_48_65537_4096
generate_certificate dsc sha384 rsapss 48 65537 3072 --signer sha384_rsapss_48_65537_3072
generate_certificate csca sha512 rsapss 64 65537 4096
generate_certificate dsc sha512 rsapss 64 65537 4096 --signer sha512_rsapss_64_65537_4096
generate_certificate dsc sha512 rsapss 64 65537 2048 --signer sha512_rsapss_64_65537_4096
# ECDSA certificates
generate_certificate csca sha224 ecdsa secp224r1
generate_certificate dsc sha224 ecdsa secp224r1 --signer sha224_ecdsa_secp224r1
generate_certificate csca sha1 ecdsa secp256r1
generate_certificate dsc sha1 ecdsa secp256r1 --signer sha1_ecdsa_secp256r1
generate_certificate csca sha256 ecdsa secp256r1
generate_certificate dsc sha256 ecdsa secp256r1 --signer sha256_ecdsa_secp256r1
generate_certificate csca sha256 ecdsa secp384r1
generate_certificate dsc sha256 ecdsa secp384r1 --signer sha256_ecdsa_secp384r1
generate_certificate csca sha384 ecdsa secp384r1
generate_certificate dsc sha384 ecdsa secp384r1 --signer sha384_ecdsa_secp384r1
generate_certificate csca sha256 ecdsa secp521r1
generate_certificate dsc sha256 ecdsa secp521r1 --signer sha256_ecdsa_secp521r1
generate_certificate csca sha512 ecdsa secp521r1
generate_certificate dsc sha512 ecdsa secp521r1 --signer sha512_ecdsa_secp521r1
# Brainpool ECDSA certificates
generate_certificate csca sha1 ecdsa brainpoolP224r1
generate_certificate dsc sha1 ecdsa brainpoolP224r1 --signer sha1_ecdsa_brainpoolP224r1
generate_certificate csca sha224 ecdsa brainpoolP224r1
generate_certificate dsc sha224 ecdsa brainpoolP224r1 --signer sha224_ecdsa_brainpoolP224r1
generate_certificate csca sha256 ecdsa brainpoolP224r1
generate_certificate csca sha1 ecdsa brainpoolP256r1
generate_certificate dsc sha1 ecdsa brainpoolP256r1 --signer sha1_ecdsa_brainpoolP256r1
generate_certificate dsc sha256 ecdsa brainpoolP224r1 --signer sha256_ecdsa_brainpoolP224r1
generate_certificate csca sha256 ecdsa brainpoolP256r1
generate_certificate dsc sha256 ecdsa brainpoolP256r1 --signer sha256_ecdsa_brainpoolP256r1
generate_certificate csca sha384 ecdsa brainpoolP256r1
generate_certificate dsc sha384 ecdsa brainpoolP256r1 --signer sha384_ecdsa_brainpoolP256r1
generate_certificate csca sha512 ecdsa brainpoolP256r1
generate_certificate dsc sha512 ecdsa brainpoolP256r1 --signer sha512_ecdsa_brainpoolP256r1
generate_certificate csca sha256 ecdsa brainpoolP384r1
generate_certificate dsc sha256 ecdsa brainpoolP384r1 --signer sha256_ecdsa_brainpoolP384r1
generate_certificate csca sha384 ecdsa brainpoolP384r1
generate_certificate dsc sha384 ecdsa brainpoolP384r1 --signer sha384_ecdsa_brainpoolP384r1
generate_certificate csca sha512 ecdsa brainpoolP384r1
generate_certificate dsc sha512 ecdsa brainpoolP384r1 --signer sha512_ecdsa_brainpoolP384r1
generate_certificate csca sha384 ecdsa brainpoolP512r1
generate_certificate dsc sha384 ecdsa brainpoolP512r1 --signer sha384_ecdsa_brainpoolP512r1
generate_certificate csca sha512 ecdsa brainpoolP512r1
generate_certificate dsc sha512 ecdsa brainpoolP512r1 --signer sha512_ecdsa_brainpoolP512r1


##
echo -e "\033[32mMock certificates generated\033[0m"
python src/scripts/addCertificatesInTs.py
echo -e "\033[32mCertificates added in certificates.ts\033[0m"


# Parse command line arguments
CSCA_FLAG=false
for arg in "$@"; do
    case $arg in
        --csca)
            CSCA_FLAG=true
            shift # Remove --csca from processing
            ;;
    esac
done

if [ "$CSCA_FLAG" = true ]; then
    cd ../registry
    ts-node src/buildSkiPem.ts
    echo -e "\033[32mSkiPem generated\033[0m"
    cd ../common
    python src/scripts/addSkiPemToTs.py
    echo -e "\033[32mSkiPem added in certificates.ts\033[0m"
    cd ../registry
fi


cd ../registry
    ts-node src/dsc/build_dsc_merkle_tree.ts
    echo -e "\033[32mDSC Merkle tree updated\033[0m"
cd ../common


if [ "$CSCA_FLAG" = true ]; then
    cd ../registry
    ts-node src/csca/build_csca_merkle_tree.ts
    echo -e "\033[32mCSCA Merkle tree updated\033[0m"
fi