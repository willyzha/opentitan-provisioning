#!/bin/bash
# Copyright lowRISC contributors (OpenTitan project).
# Licensed under the Apache License, Version 2.0, see LICENSE for details.
# SPDX-License-Identifier: Apache-2.0

set -e

# The script must be executed from its local directory.
usage () {
  echo "Usage: $0 --input_tar <input.tar.gz[:input2.tar.gz...]> --output_tar <output.tar.gz>"
  echo "  --hsm_module <pkcs.some>     Path to the PKCS#11 module."
  echo "  --token <token>              Token name."
  echo "  --softhsm_config <config>    Path to the SoftHSM config file. Optional."
  echo "  --hsm_pin <pin>              PIN for the token."
  echo "  --input_tar <input.tar.gz[:input2.tar.gz...]> Path to the input tarball(s), separated by colons. Optional."
  echo "  --output_tar <output.tar.gz> Path to the output tarball. Optional."
  echo "  --csr_only                   Only export CSRs, do not sign them. Optional."
  echo "  --sign_only                  Only sign certificates, skip CSR generation. Optional."
  echo "  --help                       Show this help message."
  exit 1
}

readonly OUTDIR_CA="ca"

readonly CERTGEN_TEMPLATES=(@@CERTGEN_TEMPLATES@@)
readonly CERTGEN_KEYS=(@@CERTGEN_KEYS@@)
readonly CERTGEN_ENDORSING_KEYS=(@@CERTGEN_ENDORSING_KEYS@@)

FLAGS_HSMTOOL_MODULE=""
FLAGS_HSMTOOL_TOKEN=""
FLAGS_SOFTHSM_CONFIG=""
FLAGS_HSMTOOL_PIN=""
FLAGS_IN_TAR=""
FLAGS_OUT_TAR=""
FLAGS_CSR_ONLY=false
FLAGS_SIGN_ONLY=false

LONGOPTS="hsm_module:,token:,softhsm_config:,hsm_pin:,input_tar:,output_tar:,csr_only,sign_only,help"
OPTS=$(getopt -o "" --long "${LONGOPTS}" -n "$0" -- "$@")

if [ $? != 0 ] ; then echo "Failed parsing options." >&2 ; exit 1 ; fi

eval set -- "$OPTS"

while true; do
  case "$1" in
    --hsm_module)
      FLAGS_HSMTOOL_MODULE="$2"
      shift 2
      ;;
    --token)
      FLAGS_HSMTOOL_TOKEN="$2"
      shift 2
      ;;
    --softhsm_config)
      FLAGS_SOFTHSM_CONFIG="$2"
      shift 2
      ;;
    --hsm_pin)
      FLAGS_HSMTOOL_PIN="$2"
      shift 2
      ;;
    --input_tar)
      FLAGS_IN_TAR="$2"
      shift 2
      ;;
    --output_tar)
      FLAGS_OUT_TAR="$2"
      shift 2
      ;;
    --csr_only)
      FLAGS_CSR_ONLY=true
      shift
      ;;
    --sign_only)
      FLAGS_SIGN_ONLY=true
      shift
      ;;
    --help)
      usage
      ;;
    --)
      shift
      break
      ;;
    *)
      usage
      ;;
  esac
done
shift $((OPTIND - 1))

if [[ "$#" -gt 0 ]]; then
  echo "Unexpected arguments:" "$@" >&2
  exit 1
fi

if [[ -z "${FLAGS_HSMTOOL_MODULE}" ]]; then
  echo "Error: -m HSMTOOL_MODULE is not set."
  exit 1
fi

if [[ -z "${FLAGS_HSMTOOL_TOKEN}" ]]; then
  echo "Error: -t HSMTOOL_TOKEN is not set."
  exit 1
fi

if [[ -z "${FLAGS_HSMTOOL_PIN}" ]]; then
  echo "Error: -p HSMTOOL_PIN is not set."
  exit 1
fi

if [[ ${#CERTGEN_TEMPLATES[@]} -ne ${#CERTGEN_ENDORSING_KEYS[@]} ]]; then
  echo "Error: Number of certgen templates and endorsing keys do not match."
  exit 1
fi

if [[ "${FLAGS_CSR_ONLY}" == true ]] && [[ "${FLAGS_SIGN_ONLY}" == true ]]; then
  echo "Error: --csr_only and --sign_only cannot be used together."
  exit 1
fi

if [[ -n "${FLAGS_OUT_TAR}" && "${FLAGS_OUT_TAR}" != *.tar.gz  ]]; then
  echo "Error: Output tarball must have .tar.gz extension."
  exit 1
fi

if [[ -n "${FLAGS_IN_TAR}" ]]; then
  IFS=':' read -ra TAR_FILES <<< "${FLAGS_IN_TAR}"
  for tar_file in "${TAR_FILES[@]}"; do
    if [[ "${tar_file}" != *.tar.gz  ]]; then
      echo "Error: Input tarball '${tar_file}' must have .tar.gz extension."
      exit 1
    fi
    if [[ ! -f "${tar_file}" ]]; then
      echo "Error: Input tarball '${tar_file}' does not exist."
      exit 1
    fi
    echo "Extracting input tarball ${tar_file}"
    tar -xzf "${tar_file}"
  done
fi


# Create output directory for HSM exported files.
mkdir -p "${OUTDIR_CA}"

# If the GEM engine is used, we need to initialize a session with the HSM.
# The following variable is used to track if the session has been initialized.
# The close_gem_engine_session function will be called on exit to close the session.
CA_GEM_ENGINE_INIT=false
close_gem_engine_session () {
  if [ "${OTPROV_USE_GEM_ENGINE}" == true ] && [ "${CA_GEM_ENGINE_INIT}" == true ]; then
    echo "Closing Gem engine session."
    sautil -s "${OTPROV_GEM_SLOT_CERT_OPS}" -i 10:11 -c
    CA_GEM_ENGINE_INIT=false
  fi
}
trap close_gem_engine_session EXIT

if [ "${OTPROV_USE_GEM_ENGINE}" == true ]; then
  if ! command -v "sautil" &> /dev/null; then
    echo "Error: Required command 'sautil' is not installed or not in your PATH." >&2
    exit 1
  fi

  if [[ -z "${OTPROV_GEM_SLOT_CERT_OPS}" ]]; then
    echo "Error: -p OTPROV_GEM_SLOT_CERT_OPS is not set."
    exit 1
  fi

  # Initialize a session with the HSM using the sautil command. Provided by
  # the Gem engine.
  # The user is expected to set this environment variable to set the correct
  # HSM slot for certificate operations.
  sautil -s "${OTPROV_GEM_SLOT_CERT_OPS}" -i 10:11 -o -p "${FLAGS_HSMTOOL_PIN}"
  CA_GEM_ENGINE_INIT=true
fi


# certgen generates a certificate for the given config file and signs it with
# the given CA key.
certgen () {
  config_basename="${1%.conf}"
  ca_key="${2}"
  endorsing_key="${3}"

  certvars=()
  if [[ -n "${FLAGS_SOFTHSM_CONFIG}" ]]; then
    certvars+=(SOFTHSM2_CONF="${FLAGS_SOFTHSM_CONFIG}")
  fi
  certvars+=(
    PKCS11_MODULE_PATH="${FLAGS_HSMTOOL_MODULE}"
  )

  # Check if we should use Gem engine or PKCS#11 provider.
  USE_GEM=false
  if [ "${OTPROV_USE_GEM_ENGINE}" == true ]; then
    USE_GEM=true
  fi

  KEY="pkcs11:pin-value=${FLAGS_HSMTOOL_PIN};object=${ca_key};token=${FLAGS_HSMTOOL_TOKEN}"
  if [ "${USE_GEM}" == true ]; then
    KEY="${ca_key}"
  fi

  CONFIG_FILE="${config_basename}.conf"
  CSR_FILE="${OUTDIR_CA}/${ca_key}.csr"
  CERT_FILE="${OUTDIR_CA}/${ca_key}.pem"

  # Helper to check if key is MLDSA
  is_mldsa_key() {
    [[ "$1" == *"-mldsa-"* ]]
  }

  if [[ "${FLAGS_SIGN_ONLY}" == false ]]; then
    # Generate a CSR for the CA key.
    echo "Generating CSR for ${ca_key}"
    if [ "${USE_GEM}" == true ]; then
        env "${certvars[@]}" \
        openssl req -new -engine "gem" -keyform engine \
            -config "${CONFIG_FILE}" \
            -out "${CSR_FILE}" \
            -key "${KEY}"
    elif is_mldsa_key "${ca_key}"; then
        # Use hsmtool for MLDSA CSR generation.
        # Parse DN from config file.
        # Format expected: C=US, ST=CA, O=Google, OU=Engineering, CN=Google Engineering ICA
        # The config file has:
        # [dn]
        # C=US
        # ...
        C=$(grep "^C=" "${CONFIG_FILE}" | cut -d= -f2 | tr -d '\r')
        ST=$(grep "^ST=" "${CONFIG_FILE}" | cut -d= -f2 | tr -d '\r')
        O=$(grep "^O=" "${CONFIG_FILE}" | cut -d= -f2 | tr -d '\r')
        OU=$(grep "^OU=" "${CONFIG_FILE}" | cut -d= -f2 | tr -d '\r')
        CN=$(grep "^CN=" "${CONFIG_FILE}" | cut -d= -f2 | tr -d '\r')
        SUBJ="C=${C},ST=${ST},O=${O},OU=${OU},CN=${CN}"

        # Assuming HSMTOOL_BIN is available via runfiles/environment.
        # If not, we might need to rely on the fact that this script is run by token_init which sets it.
        # But inside Bazel build, we need to ensure we use the binary passed in via runfiles.
        # The rule `hsm_certgen_script` provided `_hsmtool`.
        # Its path should be resolved.
        # We can try finding it or expect it in path.
        HSMTOOL_CMD="hsmtool"
        if [[ -x "third_party/hsmtool/hsmtool" ]]; then
           HSMTOOL_CMD="./third_party/hsmtool/hsmtool"
        elif [[ -n "${HSMTOOL_BIN}" ]]; then
           HSMTOOL_CMD="${HSMTOOL_BIN}"
        fi

        "${HSMTOOL_CMD}" --module "${FLAGS_HSMTOOL_MODULE}" --token "${FLAGS_HSMTOOL_TOKEN}" --pin "${FLAGS_HSMTOOL_PIN}" \
            mldsa export-csr --label "${ca_key}" --subject "${SUBJ}" --output "${CSR_FILE}"
    else
        # Use Engine for others (ECDSA/RSA)
        env "${certvars[@]}" \
        openssl req -new -engine "pkcs11" -keyform engine \
            -config "${CONFIG_FILE}" \
            -out "${CSR_FILE}" \
            -key "${KEY}"
    fi
  else
    # Running in sign only mode...
    if [[ ! -f "${CSR_FILE}" ]]; then
      echo "Error: CSR file ${CSR_FILE} does not exist."
      exit 1
    fi
  fi

  # Skip certificate signing if we are only generating CSRs.
  if [[ "${FLAGS_CSR_ONLY}" == true ]]; then
    return
  fi

  ENDORSING_KEY="pkcs11:pin-value=${FLAGS_HSMTOOL_PIN};object=${endorsing_key};token=${FLAGS_HSMTOOL_TOKEN}"
  if [ "${USE_GEM}" == true ]; then
    ENDORSING_KEY="${endorsing_key}"
  fi

  if [[ "${ca_key}" == "${endorsing_key}" ]]; then
    echo "Generating root CA certificate for ${ca_key}"
    if [ "${USE_GEM}" == true ]; then
        env "${certvars[@]}" \
        openssl x509 -req -engine "gem" -keyform engine \
        -in "${CSR_FILE}" \
        -out "${CERT_FILE}" \
        -days 7300 \
        -extfile "${CONFIG_FILE}" \
        -extensions v3_ca \
        -signkey "${ENDORSING_KEY}"
    elif is_mldsa_key "${endorsing_key}"; then
        env "${certvars[@]}" \
        openssl x509 -req -provider pkcs11 -provider default \
        -in "${CSR_FILE}" \
        -out "${CERT_FILE}" \
        -days 7300 \
        -extfile "${CONFIG_FILE}" \
        -extensions v3_ca \
        -signkey "${ENDORSING_KEY}"
    else
        env "${certvars[@]}" \
        openssl x509 -req -engine "pkcs11" -keyform engine \
        -in "${CSR_FILE}" \
        -out "${CERT_FILE}" \
        -days 7300 \
        -extfile "${CONFIG_FILE}" \
        -extensions v3_ca \
        -signkey "${ENDORSING_KEY}"
    fi
  else
    echo "Generating certificate for ${ca_key} signed by ${endorsing_key}"

    CA_ENDORSING_CERT_FILE="${OUTDIR_CA}/${endorsing_key}.pem"
    if [[ ! -f "${CA_ENDORSING_CERT_FILE}" ]]; then
      echo "Error: CA endorsing certificate file ${CA_ENDORSING_CERT_FILE} does not exist."
      exit 1
    fi

    if [ "${USE_GEM}" == true ]; then
        env "${certvars[@]}" \
        openssl x509 -req -engine "gem" -keyform engine \
        -in "${CSR_FILE}" \
        -out "${CERT_FILE}" \
        -days 7300 \
        -extfile "${CONFIG_FILE}" \
        -extensions v3_ca \
        -CA "${CA_ENDORSING_CERT_FILE}" \
        -CAkeyform engine \
        -CAkey "${ENDORSING_KEY}"
    elif is_mldsa_key "${endorsing_key}"; then
        env "${certvars[@]}" \
        openssl x509 -req -provider pkcs11 -provider default \
        -in "${CSR_FILE}" \
        -out "${CERT_FILE}" \
        -days 7300 \
        -extfile "${CONFIG_FILE}" \
        -extensions v3_ca \
        -CA "${CA_ENDORSING_CERT_FILE}" \
        -CAkey "${ENDORSING_KEY}"
    else
        env "${certvars[@]}" \
        openssl x509 -req -engine "pkcs11" -keyform engine \
        -in "${CSR_FILE}" \
        -out "${CERT_FILE}" \
        -days 7300 \
        -extfile "${CONFIG_FILE}" \
        -extensions v3_ca \
        -CA "${CA_ENDORSING_CERT_FILE}" \
        -CAkeyform engine \
        -CAkey "${ENDORSING_KEY}"
    fi
  fi

  echo "Converting certificate for ${ca_key} to DER"
  openssl x509 -in "${CERT_FILE}" -outform DER -out "${OUTDIR_CA}/${ca_key}.der"
}

for i in "${!CERTGEN_TEMPLATES[@]}"; do
  template="${CERTGEN_TEMPLATES[$i]}"
  key="${CERTGEN_KEYS[$i]}"
  endorsing_key="${CERTGEN_ENDORSING_KEYS[$i]}"

  echo "Generating certificate for ${template}"
  certgen "${template}" "${key}" "${endorsing_key}"
done

if [[ -n "${FLAGS_OUT_TAR}" ]]; then
  echo "Exporting HSM data to ${FLAGS_OUT_TAR}"
  tar -czvf "${FLAGS_OUT_TAR}" "${OUTDIR_CA}"
fi

