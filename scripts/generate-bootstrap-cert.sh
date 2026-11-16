#!/usr/bin/env bash
set -euo pipefail

# * SPDX-License-Identifier: Apache-2.0
# * © Crown Copyright 2026. This work has been developed by the National Digital Twin Programme and is legally
# * attributed to the UK's Department for Business, Innovation, Science and Trade (BIST) as the governing entity.
#
###############################################################################
# Bootstrap Certificate Test Utility
#
# Purpose
# -------
# This script creates a test environment that mimics the state where an
# application possesses a freshly issued bootstrap client certificate.
#
# It is intended for testing behaviour such as:
#   - X509 authentication with Keycloak
#   - mTLS client authentication
#   - certificate expiry handling
#   - application bootstrap flows
#
# The script generates:
#
#   keystore.p12
#       Contains the client private key and certificate (unless empty mode)
#
#   truststore.p12
#       Contains the Root CA and optionally the bootstrap certificate
#
# The bootstrap certificate is issued by an existing Root CA and has a short
# configurable validity window (typically 5 minutes) to allow expiry testing.
#
# Flags
# -----
# --clean
#     Removes previously generated files in the target directory.
#
# --empty-keystore
#     Skips bootstrap certificate creation and instead creates an empty
#     PKCS12 keystore. This is useful for testing application behaviour when
#     no client certificate is available.
#
# Usage
# -----
#
#   ./bootstrap-cert.sh [flags] <target_dir> <validity_minutes> <root_ca_dir>
#
# Example
#
#   ./bootstrap-cert.sh ./state 5 ./ca
#
#   ./bootstrap-cert.sh --clean ./state 5 ./ca
#
#   ./bootstrap-cert.sh --clean --empty-keystore ./state 5 ./ca
#
###############################################################################

CLEAN=false
EMPTY_KEYSTORE=false

# ---- optional flags ----
while [[ "${1:-}" == --* ]]; do
  case "$1" in
    --clean)
      CLEAN=true
      shift
      ;;
    --empty-keystore)
      EMPTY_KEYSTORE=true
      shift
      ;;
    *)
      echo "Unknown flag: $1"
      exit 1
      ;;
  esac
done

# ---- args ----
if [ "$#" -ne 5 ]; then
  echo "Usage: $0 [--clean] [--empty-keystore] <target_dir> <validity_minutes> <root_ca_dir> <keystore_pass> <truststore_pass>"
  exit 1
fi

TARGET_DIR="$1"
VALIDITY_MINUTES="$2"
ROOT_CA_DIR="$3"
KEYSTOREPASS="$4"
TRUSTSTOREPASS="$5"


ROOT_CRT="$ROOT_CA_DIR/rootCA.crt"
ROOT_KEY="$ROOT_CA_DIR/rootCA.key"

# ---- config ----
ALIAS="bootstrap"
CN="api.acme-digital.co.uk"

KEY="$TARGET_DIR/bootstrap.key"
CSR="$TARGET_DIR/bootstrap.csr"
CERT="$TARGET_DIR/bootstrap.crt"
KEYSTORE="$TARGET_DIR/keystore.p12"
TRUSTSTORE="$TARGET_DIR/truststore.p12"
TMP_P12="$TARGET_DIR/bootstrap.p12"

mkdir -p "$TARGET_DIR"
chmod 750 "$TARGET_DIR"

# ---- cleanup (optional) ----
if [ "$CLEAN" = true ]; then
  echo "Cleaning previous bootstrap artifacts"

  rm -f \
    "$KEY" \
    "$CSR" \
    "$CERT" \
    "$KEYSTORE" \
    "$TRUSTSTORE" \
    "$TMP_P12"
fi

# ---- ephemeral CA state ----
CA_STATE_DIR=$(mktemp -d)
trap 'rm -rf "$CA_STATE_DIR"' EXIT

mkdir -p "$CA_STATE_DIR/newcerts"
touch "$CA_STATE_DIR/index.txt"
echo 1000 > "$CA_STATE_DIR/serial"

CA_CONF="$CA_STATE_DIR/ca.cnf"

cat > "$CA_CONF" <<EOF
[ ca ]
default_ca = CA_default

[ CA_default ]
dir               = $CA_STATE_DIR
database          = \$dir/index.txt
new_certs_dir     = \$dir/newcerts
serial            = \$dir/serial

certificate       = $ROOT_CRT
private_key       = $ROOT_KEY
default_md        = sha256
policy            = policy_any
x509_extensions   = bootstrap_ext
copy_extensions   = none

[ policy_any ]
commonName = supplied

[ bootstrap_ext ]
basicConstraints = CA:FALSE
keyUsage = digitalSignature
extendedKeyUsage = clientAuth
EOF

if [ "$EMPTY_KEYSTORE" = false ]; then

  # ---- validity window ----
  START_DATE=$(date -u +"%Y%m%d%H%M%SZ")
  END_DATE=$(date -u -d "+${VALIDITY_MINUTES} minutes" +"%Y%m%d%H%M%SZ")

  echo "Generating private key"
  openssl genrsa -out "$KEY" 2048

  echo "Creating CSR"
  openssl req -new \
    -key "$KEY" \
    -out "$CSR" \
    -subj "/CN=${CN}"

  echo "Issuing bootstrap certificate (${VALIDITY_MINUTES} minutes)"
  openssl ca \
    -config "$CA_CONF" \
    -in "$CSR" \
    -out "$CERT" \
    -startdate "$START_DATE" \
    -enddate "$END_DATE" \
    -batch

  echo "Creating keystore"
  openssl pkcs12 -export \
    -inkey "$KEY" \
    -in "$CERT" \
    -name "$ALIAS" \
    -out "$TMP_P12" \
    -passout pass:"$KEYSTOREPASS"

  keytool -importkeystore \
    -destkeystore "$KEYSTORE" \
    -deststoretype PKCS12 \
    -deststorepass "$KEYSTOREPASS" \
    -srckeystore "$TMP_P12" \
    -srcstoretype PKCS12 \
    -srcstorepass "$KEYSTOREPASS"

else

  echo "Creating empty PKCS12 keystore"

  keytool -genkeypair \
    -alias temp-entry \
    -keyalg RSA \
    -keystore "$KEYSTORE" \
    -storetype PKCS12 \
    -storepass "$KEYSTOREPASS" \
    -dname "CN=temp" \
    -validity 1

  keytool -delete \
    -alias temp-entry \
    -keystore "$KEYSTORE" \
    -storepass "$KEYSTOREPASS"

fi

echo "Creating truststore"

keytool -importcert \
  -file "$ROOT_CRT" \
  -alias rootca \
  -keystore "$TRUSTSTORE" \
  -storetype PKCS12 \
  -storepass "$TRUSTSTOREPASS" \
  -noprompt

if [ "$EMPTY_KEYSTORE" = false ]; then
  keytool -importcert \
    -alias "$ALIAS" \
    -file "$CERT" \
    -keystore "$TRUSTSTORE" \
    -storetype PKCS12 \
    -storepass "$TRUSTSTOREPASS" \
    -noprompt
fi

rm -f "$TMP_P12"

echo "  Bootstrap test state created"
echo "  Keystore:   $KEYSTORE"
echo "  Truststore: $TRUSTSTORE"

if [ "$EMPTY_KEYSTORE" = false ]; then
  echo "  Validity:   $START_DATE → $END_DATE"
else
  echo "  Keystore created empty (--empty-keystore)"
fi