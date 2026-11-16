#!/usr/bin/env bash
#
# SPDX-License-Identifier: Apache-2.0
# © Crown Copyright 2026. This work has been developed by the National Digital Twin Programme and is legally
# attributed to the UK's Department for Business, Innovation, Science and Trade (BIST) as the governing entity.
#

# Prepare Vault for the certificate manager: issue a bootstrap certificate from the Management Node and
# write the secrets the application reads at start-up, using the Vault HTTP API.
#
# Secrets written (KV v2), under --vault-path (= application.vault.secret-path, e.g. node-net/client,
# where the first segment is the KV mount):
#   <path>/keypair              {publicKey, privateKey}     VaultSecretProviderImpl.getKeyPair
#   <path>/certificate          {certificate}               VaultSecretProviderImpl.getCertificate
#   <path>/ca-chain             {chain}                     VaultSecretProviderImpl.getCaChain
#   <path>/intermediate-ca      {certificate}               VaultSecretProviderImpl.getIntermediateCa
#   <path>/keystore-password    {password}                  KeyStoreSyncServiceImpl / MtlsHttpClientBuilder
#   <path>/truststore-password  {password}                  KeyStoreSyncServiceImpl / MtlsHttpClientBuilder
#
# On start-up the renewal job sees the bootstrap OID in the certificate and replaces it with a regular
# certificate straight away; the sync job builds the keystore and truststore from these secrets.
#
# Flow (Management Node calls over mTLS with the client certificate):
#   1. POST {IDP_URL}                                  client_credentials token
#   2. GET  {MN_URL}/api/v1/certificate/keyPair        RSA key pair       (role create_keys)
#   3. POST {MN_URL}/api/v1/certificate/csr/create     CSR from that pair (role create_keys)
#   4. POST {MN_URL}/api/v1/certificate/bootstrap      ZIP: certificate.pem + ca-chain.pem
#                                                      (role request_bootstrap_certificate)
#   5. GET  {MN_URL}/api/v1/certificate/intermediate   signing CA (role access_public_certificates);
#                                                      falls back to the certificate's issuer in the chain
#   6. Vault: check the KV v2 mount, then write the six secrets
#
# Usage:
#   bash scripts/bootstrap-vault.sh [options]
#
# Vault options (each also settable by the environment variable in brackets):
#   --vault-addr <url>        Vault address                       [VAULT_ADDR]       http://localhost:8200
#   --vault-token <token>     Vault token (prefer the env var)    [VAULT_TOKEN]      required
#   --vault-namespace <ns>    Vault Enterprise namespace          [VAULT_NAMESPACE]  (none)
#   --vault-path <path>       <kv-mount>/<base path>; must equal application.vault.secret-path
#                             [VAULT_SECRET_PATH]                 node-net/client
#   --vault-cacert <file>     CA bundle to verify Vault's TLS     [VAULT_CACERT]
#   --create-mount            enable KV v2 at the mount if it is missing [CREATE_MOUNT=1]
#   --force                   overwrite an existing certificate in Vault [FORCE=1]
#   --no-vault                only issue and write files, do not touch Vault [NO_VAULT=1]
#   --from-dir <dir>          skip issuing; push an earlier run's output dir to Vault [FROM_DIR]
#
# Issuing options:
#   --idp-url <url>           token endpoint                      [IDP_URL]
#                             https://localhost:8443/realms/mng-node/protocol/openid-connect/token
#   --mn-url <url>            Management Node base URL            [MN_URL]           https://localhost:8090
#   --client-id <id>          OAuth client id                     [CLIENT_ID]        FEDERATOR_ENV
#   --cacert <file>           extra CA to trust for the IDP and Management Node, on top of the system CAs
#                             [CA_CERT]  /home/developer/IdeaProjects/management-node/docker/cert/rootCA.crt
#   --client-secret <s>       client secret, if the client has one [CLIENT_SECRET]   (none: mTLS client auth)
#   --org-id <id>             target organisationId               [ORGANISATION_ID]  2
#   --cert <file>             client certificate for mTLS         [CLIENT_CERT]      $CERT_DIR_DEFAULT/client-org1.crt
#   --key <file>              client private key for mTLS         [CLIENT_KEY]       $CERT_DIR_DEFAULT/client-org1.key
#                             [CERT_DIR_DEFAULT] directory holding the client cert and key   /tmp
#                             e.g. the dev IDP certs in ndtp-application-continuous-delivery
#                             (applications/environments/dev/ia-node/workload/core/5-management-node/idp/certs)
#   --cn <name>               CSR commonName                      [CSR_CN]           api.acme-digital.co.uk
#   --org <name>              CSR organization (O)                [CSR_O]            Acme Digital Solutions Ltd
#   --ou <name>               CSR organizationalUnit (OU)         [CSR_OU]           Platform Engineering
#   --country <cc>            CSR country (C)                     [CSR_C]            UK
#   --email <addr>            CSR email                           [CSR_EMAIL]        (none)
#   --key-size <bits>         CSR keySize                         [CSR_KEY_SIZE]     2048
#   --key-usage <usage>       CSR keyUsage                        [CSR_KEY_USAGE]    digitalSignature
#   --san <dns>               CSR dnsSans entry, repeatable; the first one replaces the defaults
#                             [CSR_SANS, comma separated]  api.acme-digital.co.uk,api.internal.acme-digital.co.uk
#   --alias <name>            keystore alias                      [KEY_ALIAS]        federator
#   --keystore-password <p>   keystore password                   [KEYSTORE_PASSWORD]   existing in Vault, else random
#   --truststore-password <p> truststore password                 [TRUSTSTORE_PASSWORD] existing in Vault, else random
#   --out <dir>               output directory                    [OUT_DIR]          ./bootstrap-vault-<timestamp>
#   --insecure                skip server certificate verification (IDP, Management Node and Vault) [INSECURE=1]
#   -h, --help                show this help
#
# Output, in the output directory (keep it private, it holds the private key):
#   private-key.pem, public-key.pem, csr.pem, certificate.pem, ca-chain.pem, intermediate-ca.pem
#   keystore.p12, truststore.p12, keystore.password, truststore.password
#       the stores the sync job would build, for use as application.client.key-store / trust-store
#       if the client keystore must exist before the application's first Management Node call
#
# Requires: curl, jq, unzip, openssl, and keytool (a JDK) or openssl 3.2+ for the truststore.

set -euo pipefail

VAULT_ADDR="${VAULT_ADDR:-http://localhost:8200}"
VAULT_TOKEN="${VAULT_TOKEN:-}"
VAULT_NAMESPACE="${VAULT_NAMESPACE:-}"
VAULT_SECRET_PATH="${VAULT_SECRET_PATH:-node-net/client}"
VAULT_CACERT="${VAULT_CACERT:-}"
CREATE_MOUNT="${CREATE_MOUNT:-0}"
FORCE="${FORCE:-0}"
NO_VAULT="${NO_VAULT:-0}"
FROM_DIR="${FROM_DIR:-}"

IDP_URL="${IDP_URL:-https://localhost:8443/realms/mng-node/protocol/openid-connect/token}"
MN_URL="${MN_URL:-https://localhost:8090}"
CLIENT_ID="${CLIENT_ID:-FEDERATOR_ENV}"
CA_CERT="${CA_CERT:-/rootCA.crt}"
CERT_DIR_DEFAULT="${CERT_DIR_DEFAULT:-/tmp}"

CLIENT_SECRET="${CLIENT_SECRET:-}"
ORGANISATION_ID="${ORGANISATION_ID:-2}"
CLIENT_CERT="${CLIENT_CERT:-$CERT_DIR_DEFAULT/client-org1.crt}"
CLIENT_KEY="${CLIENT_KEY:-$CERT_DIR_DEFAULT/client-org1.key}"
CSR_CN="${CSR_CN:-api.acme-digital.co.uk}"
CSR_O="${CSR_O:-Acme Digital Solutions Ltd}"
CSR_OU="${CSR_OU:-Platform Engineering}"
CSR_C="${CSR_C:-UK}"
CSR_EMAIL="${CSR_EMAIL:-}"
CSR_KEY_SIZE="${CSR_KEY_SIZE:-2048}"
CSR_KEY_USAGE="${CSR_KEY_USAGE:-digitalSignature}"
CSR_SANS="${CSR_SANS-api.acme-digital.co.uk,api.internal.acme-digital.co.uk}"
SANS_FROM_FLAGS=0
KEY_ALIAS="${KEY_ALIAS:-federator}"
KEYSTORE_PASSWORD="${KEYSTORE_PASSWORD:-}"
TRUSTSTORE_PASSWORD="${TRUSTSTORE_PASSWORD:-}"
OUT_DIR="${OUT_DIR:-}"
INSECURE="${INSECURE:-0}"

usage() { awk 'NR >= 8 && /^#/ { sub(/^# ?/, ""); print; next } NR > 8 { exit }' "$0"; }

die() {
  echo "ERROR: $*" >&2
  exit 1
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --vault-addr) VAULT_ADDR="${2:?}"; shift 2 ;;
    --vault-token) VAULT_TOKEN="${2:?}"; shift 2 ;;
    --vault-namespace) VAULT_NAMESPACE="${2:?}"; shift 2 ;;
    --vault-path) VAULT_SECRET_PATH="${2:?}"; shift 2 ;;
    --vault-cacert) VAULT_CACERT="${2:?}"; shift 2 ;;
    --create-mount) CREATE_MOUNT=1; shift ;;
    --force) FORCE=1; shift ;;
    --no-vault) NO_VAULT=1; shift ;;
    --from-dir) FROM_DIR="${2:?}"; shift 2 ;;
    --cacert) CA_CERT="${2:?}"; shift 2 ;;
    --idp-url) IDP_URL="${2:?}"; shift 2 ;;
    --mn-url) MN_URL="${2:?}"; shift 2 ;;
    --client-id) CLIENT_ID="${2:?}"; shift 2 ;;
    --client-secret) CLIENT_SECRET="${2:?}"; shift 2 ;;
    --org-id) ORGANISATION_ID="${2:?}"; shift 2 ;;
    --cert) CLIENT_CERT="${2:?}"; shift 2 ;;
    --key) CLIENT_KEY="${2:?}"; shift 2 ;;
    --cn) CSR_CN="${2:?}"; shift 2 ;;
    --org) CSR_O="${2:?}"; shift 2 ;;
    --ou) CSR_OU="${2:?}"; shift 2 ;;
    --country) CSR_C="${2:?}"; shift 2 ;;
    --email) CSR_EMAIL="${2:?}"; shift 2 ;;
    --key-size) CSR_KEY_SIZE="${2:?}"; shift 2 ;;
    --key-usage) CSR_KEY_USAGE="${2:?}"; shift 2 ;;
    --san)
      # The first --san replaces the default SANs; later ones add to it.
      if [[ "$SANS_FROM_FLAGS" == "0" ]]; then CSR_SANS=""; SANS_FROM_FLAGS=1; fi
      CSR_SANS="${CSR_SANS:+$CSR_SANS,}${2:?}"
      shift 2
      ;;
    --alias) KEY_ALIAS="${2:?}"; shift 2 ;;
    --keystore-password) KEYSTORE_PASSWORD="${2:?}"; shift 2 ;;
    --truststore-password) TRUSTSTORE_PASSWORD="${2:?}"; shift 2 ;;
    --out) OUT_DIR="${2:?}"; shift 2 ;;
    --insecure) INSECURE=1; shift ;;
    -h | --help) usage; exit 0 ;;
    *) die "unknown option: $1 (see --help)" ;;
  esac
done

for tool in curl jq openssl; do
  command -v "$tool" >/dev/null 2>&1 || die "$tool is required but not installed"
done


# ---- Vault path: <mount>/<base>, the same split as VaultSecretProviderImpl --------------------------
VAULT_SECRET_PATH="${VAULT_SECRET_PATH#"${VAULT_SECRET_PATH%%[!/]*}"}" # strip leading '/'
VAULT_SECRET_PATH="${VAULT_SECRET_PATH%"${VAULT_SECRET_PATH##*[!/]}"}" # strip trailing '/'
VAULT_MOUNT="${VAULT_SECRET_PATH%%/*}"
if [[ "$VAULT_SECRET_PATH" == */* ]]; then VAULT_BASE="${VAULT_SECRET_PATH#*/}"; else VAULT_BASE=""; fi
[[ -n "$VAULT_MOUNT" ]] || die "--vault-path must be <kv-mount>/<base path>, e.g. node-net/client"
VAULT_ADDR="${VAULT_ADDR%/}"

if [[ "$NO_VAULT" != "1" ]]; then
  [[ -n "$VAULT_TOKEN" ]] || die "VAULT_TOKEN (or --vault-token) is required to write to Vault (or pass --no-vault)"
  [[ -z "$VAULT_CACERT" || -r "$VAULT_CACERT" ]] || die "Vault CA bundle not readable: $VAULT_CACERT"
fi

umask 077

# ---- Vault API -------------------------------------------------------------------------------------
VAULT_HEADERS=""
cleanup() { [[ -n "$VAULT_HEADERS" ]] && rm -f "$VAULT_HEADERS"; return 0; }
trap cleanup EXIT

vault_init() {
  # The token goes in a header file rather than on the command line, so it does not show in `ps`.
  VAULT_HEADERS="$(mktemp)"
  printf 'X-Vault-Token: %s\n' "$VAULT_TOKEN" >"$VAULT_HEADERS"
  [[ -n "$VAULT_NAMESPACE" ]] && printf 'X-Vault-Namespace: %s\n' "$VAULT_NAMESPACE" >>"$VAULT_HEADERS"
  VAULT_CURL=(--silent --show-error -H "@$VAULT_HEADERS")
  [[ -n "$VAULT_CACERT" ]] && VAULT_CURL+=(--cacert "$VAULT_CACERT")
  [[ "$INSECURE" == "1" ]] && VAULT_CURL+=(--insecure)
  return 0
}

# vault_api <method> <api path> [json body]: prints the response body; returns 0 on 2xx, 4 on 404,
# fails with the error otherwise.
vault_api() {
  local method="$1" path="$2" body="${3:-}" resp status
  local args=("${VAULT_CURL[@]}" -X "$method" --write-out '\n%{http_code}')
  [[ -n "$body" ]] && args+=(-H 'Content-Type: application/json' --data-binary @-)
  resp=$(printf '%s' "$body" | curl "${args[@]}" "$VAULT_ADDR/v1/$path") || die "Vault request failed: $method $VAULT_ADDR/v1/$path"
  status="${resp##*$'\n'}"
  resp="${resp%$'\n'*}"
  if [[ "$status" == 2* ]]; then
    printf '%s' "$resp"
    return 0
  fi
  [[ "$status" == "404" ]] && return 4
  die "Vault $method /v1/$path returned HTTP $status: $(jq -c '.errors // .' <<<"$resp" 2>/dev/null || echo "$resp")"
}

secret_rel() { if [[ -n "$VAULT_BASE" ]]; then echo "$VAULT_BASE/$1"; else echo "$1"; fi; }

# kv_get <name> <field>: prints the field of <path>/<name>, or nothing if the secret or field is absent.
kv_get() {
  local out rc=0
  out=$(vault_api GET "$VAULT_MOUNT/data/$(secret_rel "$1")") || rc=$?
  [[ "$rc" == "0" ]] || { [[ "$rc" == "4" ]] && return 0; exit "$rc"; }
  jq -r --arg f "$2" '.data.data[$f] // empty' <<<"$out"
}

# kv_put <name> <json object>: writes a new version of <path>/<name>.
kv_put() {
  vault_api POST "$VAULT_MOUNT/data/$(secret_rel "$1")" "$(jq -c '{data: .}' <<<"$2")" >/dev/null
  echo "  wrote $VAULT_MOUNT/$(secret_rel "$1")"
}

# The application only checks that the mount exists (listing sys/mounts) and uses it as KV v2.
vault_check_mount() {
  local mounts rc=0
  mounts=$(vault_api GET "sys/mounts") || rc=$?
  [[ "$rc" == "0" ]] || die "could not list Vault mounts (sys/mounts); the token needs read on it, as the application does"
  local info
  info=$(jq -c --arg m "$VAULT_MOUNT/" '.data[$m] // .[$m] // empty' <<<"$mounts")
  if [[ -z "$info" ]]; then
    [[ "$CREATE_MOUNT" == "1" ]] || die "KV mount '$VAULT_MOUNT/' not found in Vault. Create it (vault secrets enable -path=$VAULT_MOUNT kv-v2) or pass --create-mount"
    echo "  enabling KV v2 at $VAULT_MOUNT/ ..."
    vault_api POST "sys/mounts/$VAULT_MOUNT" '{"type":"kv","options":{"version":"2"}}' >/dev/null
    return 0
  fi
  local type version
  type=$(jq -r '.type' <<<"$info")
  version=$(jq -r '.options.version // "1"' <<<"$info")
  [[ "$type" == "kv" && "$version" == "2" ]] ||
    die "mount '$VAULT_MOUNT/' is type=$type version=$version; the application needs KV version 2"
}

# Check Vault before issuing a certificate, so a bad token or path does not waste one.
if [[ "$NO_VAULT" != "1" ]]; then
  vault_init
  echo "Checking Vault at $VAULT_ADDR (secrets under $VAULT_MOUNT/${VAULT_BASE}) ..."
  vault_api GET "auth/token/lookup-self" >/dev/null || die "Vault token is not valid"
  vault_check_mount
  EXISTING_CERT="$(kv_get certificate certificate)"
  if [[ -n "$EXISTING_CERT" && "$FORCE" != "1" ]]; then
    die "a certificate already exists at $VAULT_MOUNT/$(secret_rel certificate); pass --force to replace it"
  fi
fi

# ---- material: issue a new bootstrap certificate, or reuse an earlier run --------------------------
if [[ -n "$FROM_DIR" ]]; then
  OUT_DIR="$FROM_DIR"
  for f in private-key.pem public-key.pem certificate.pem ca-chain.pem; do
    [[ -s "$OUT_DIR/$f" ]] || die "$OUT_DIR/$f is missing; --from-dir needs the output of an earlier run"
  done
  echo "Using the material in $OUT_DIR (no new certificate issued)."
else
  command -v unzip >/dev/null 2>&1 || die "unzip is required but not installed"
  [[ -n "$CLIENT_CERT" && -r "$CLIENT_CERT" ]] || die "client certificate not readable (--cert / CLIENT_CERT): ${CLIENT_CERT:-<unset>}"
  [[ -n "$CLIENT_KEY" && -r "$CLIENT_KEY" ]] || die "client key not readable (--key / CLIENT_KEY): ${CLIENT_KEY:-<unset>}"
  [[ -r "$CA_CERT" ]] || die "CA certificate not readable (--cacert / CA_CERT): $CA_CERT"
  [[ "$ORGANISATION_ID" =~ ^[0-9]+$ ]] || die "organisationId must be numeric: $ORGANISATION_ID"
  [[ "$CSR_KEY_SIZE" =~ ^[0-9]+$ ]] || die "keySize must be numeric: $CSR_KEY_SIZE"

  OUT_DIR="${OUT_DIR:-./bootstrap-vault-$(date -u +%Y%m%dT%H%M%SZ)}"
  mkdir -p "$OUT_DIR"
  chmod 700 "$OUT_DIR"

  # Trust CA_CERT in addition to the system CAs, so the same setting works for servers with a private CA
  # (local) and with public certificates (cloud).
  TRUST_BUNDLE="$OUT_DIR/trust-bundle.pem"
  : >"$TRUST_BUNDLE"
  for system_bundle in /etc/ssl/certs/ca-certificates.crt /etc/pki/tls/certs/ca-bundle.crt /etc/ssl/cert.pem; do
    if [[ -r "$system_bundle" ]]; then cat "$system_bundle" >>"$TRUST_BUNDLE"; break; fi
  done
  cat "$CA_CERT" >>"$TRUST_BUNDLE"

  CURL_OPTS=(--silent --show-error --cert "$CLIENT_CERT" --key "$CLIENT_KEY" --cacert "$TRUST_BUNDLE")
  [[ "$INSECURE" == "1" ]] && CURL_OPTS+=(--insecure)
  echo "IDP $IDP_URL | Management Node $MN_URL | client $CLIENT_ID | trusting system CAs + $CA_CERT"

  # call <out-file> <curl args...>: writes the body to <out-file>; prints the HTTP status. Fails on a
  # transport error; the caller decides what a non-2xx status means.
  call_status() {
    local out="$1"
    shift
    curl "${CURL_OPTS[@]}" --output "$out" --write-out '%{http_code}' "$@" || die "request failed: curl ${*: -1}"
  }
  # call <out-file> <curl args...>: as call_status, but fails on a non-2xx status and shows the body.
  call() {
    local out="$1" status
    shift
    status=$(call_status "$out" "$@")
    if [[ "$status" != 2* ]]; then
      echo "HTTP $status from: ${*: -1}" >&2
      cat "$out" >&2 || true
      echo >&2
      exit 1
    fi
  }

  # ---- 1. token -------------------------------------------------------------------------------------
  echo "1/5 Requesting token for $CLIENT_ID ..."
  TOKEN_ARGS=(--data-urlencode "grant_type=client_credentials" --data-urlencode "client_id=$CLIENT_ID")
  [[ -n "$CLIENT_SECRET" ]] && TOKEN_ARGS+=(--data-urlencode "client_secret=$CLIENT_SECRET")
  call "$OUT_DIR/token.json" -X POST -H 'Content-Type: application/x-www-form-urlencoded' "${TOKEN_ARGS[@]}" "$IDP_URL"
  ACCESS_TOKEN=$(jq -er '.access_token' "$OUT_DIR/token.json") || die "no access_token in token response"
  AUTH=(-H "Authorization: Bearer $ACCESS_TOKEN")

  # ---- 2. key pair ----------------------------------------------------------------------------------
  echo "2/5 Creating key pair ..."
  call "$OUT_DIR/keypair.json" -X GET "${AUTH[@]}" "$MN_URL/api/v1/certificate/keyPair"
  jq -er '.privateKeyPem' "$OUT_DIR/keypair.json" >"$OUT_DIR/private-key.pem" || die "no privateKeyPem in key pair response"
  jq -er '.publicKeyPem' "$OUT_DIR/keypair.json" >"$OUT_DIR/public-key.pem" || die "no publicKeyPem in key pair response"

  # ---- 3. CSR ---------------------------------------------------------------------------------------
  echo "3/5 Creating CSR (CN=$CSR_CN) ..."
  jq -n \
    --slurpfile kp "$OUT_DIR/keypair.json" \
    --arg cn "$CSR_CN" --arg o "$CSR_O" --arg ou "$CSR_OU" --arg c "$CSR_C" --arg sans "$CSR_SANS" \
    --arg email "$CSR_EMAIL" --argjson keySize "$CSR_KEY_SIZE" --arg keyUsage "$CSR_KEY_USAGE" \
    '{
       privateKeyPem: $kp[0].privateKeyPem,
       publicKeyPem: $kp[0].publicKeyPem,
       commonName: $cn,
       country: (if $c == "" then null else $c end),
       email: (if $email == "" then null else $email end),
       keySize: $keySize,
       keyUsage: (if $keyUsage == "" then null else $keyUsage end),
       organization: (if $o == "" then null else $o end),
       organizationalUnit: (if $ou == "" then null else $ou end),
       dnsSans: ($sans | split(",") | map(select(. != "")))
     }' >"$OUT_DIR/csr-request.json"
  call "$OUT_DIR/csr.json" -X POST "${AUTH[@]}" -H 'Content-Type: application/json' \
    --data-binary "@$OUT_DIR/csr-request.json" "$MN_URL/api/v1/certificate/csr/create"
  jq -er '.csrPem' "$OUT_DIR/csr.json" >"$OUT_DIR/csr.pem" || die "no csrPem in CSR response"

  # ---- 4. bootstrap ---------------------------------------------------------------------------------
  echo "4/5 Requesting bootstrap certificate for organisation $ORGANISATION_ID ..."
  jq -n --argjson org "$ORGANISATION_ID" --rawfile csr "$OUT_DIR/csr.pem" \
    '{organisationId: $org, csr: $csr}' >"$OUT_DIR/bootstrap-request.json"
  call "$OUT_DIR/bootstrap_bundle.zip" -X POST "${AUTH[@]}" -H 'Content-Type: application/json' \
    -H 'Accept: application/zip' --data-binary "@$OUT_DIR/bootstrap-request.json" \
    "$MN_URL/api/v1/certificate/bootstrap"

  BUNDLE_DIR="$OUT_DIR/bootstrap_bundle"
  rm -rf "$BUNDLE_DIR"
  mkdir -p "$BUNDLE_DIR"
  unzip -o -q "$OUT_DIR/bootstrap_bundle.zip" -d "$BUNDLE_DIR" || die "bootstrap response is not a valid ZIP"
  [[ -s "$BUNDLE_DIR/certificate.pem" ]] || die "certificate.pem missing from bootstrap ZIP"
  [[ -s "$BUNDLE_DIR/ca-chain.pem" ]] || die "ca-chain.pem missing from bootstrap ZIP"
  cp "$BUNDLE_DIR/certificate.pem" "$OUT_DIR/certificate.pem"
  # The server joins the chain's certificates with no separator; restore the line breaks.
  sed 's/-----END CERTIFICATE-----/&\n/g' "$BUNDLE_DIR/ca-chain.pem" | sed '/^$/d' >"$OUT_DIR/ca-chain.pem"

  # ---- 5. intermediate CA ---------------------------------------------------------------------------
  # The application verifies each renewed certificate against intermediate-ca, so take it from the same
  # endpoint the application uses (ManagementNodeService.getIntermediateCertificate) when allowed.
  echo "5/5 Fetching the intermediate CA ..."
  STATUS=$(call_status "$OUT_DIR/intermediate.json" -X GET "${AUTH[@]}" "$MN_URL/api/v1/certificate/intermediate")
  if [[ "$STATUS" == 2* ]] && jq -er '.certificate | select(. != null and . != "")' "$OUT_DIR/intermediate.json" >"$OUT_DIR/intermediate-ca.pem"; then
    echo "  from $MN_URL/api/v1/certificate/intermediate"
  else
    echo "  /intermediate returned HTTP $STATUS (role access_public_certificates?); using the certificate's issuer from the CA chain"
    rm -f "$OUT_DIR/intermediate-ca.pem"
  fi

  rm -f "$OUT_DIR/token.json" "$OUT_DIR/keypair.json" "$OUT_DIR/csr.json" "$OUT_DIR/csr-request.json" \
    "$OUT_DIR/bootstrap-request.json" "$OUT_DIR/intermediate.json" "$TRUST_BUNDLE"
fi

CERT_PEM="$OUT_DIR/certificate.pem"
CA_CHAIN_PEM="$OUT_DIR/ca-chain.pem"
INTERMEDIATE_PEM="$OUT_DIR/intermediate-ca.pem"

# Split the chain into one file per certificate (ca-0 is the issuer of the certificate, upwards).
CA_SPLIT_DIR="$OUT_DIR/ca-split"
rm -rf "$CA_SPLIT_DIR"
mkdir -p "$CA_SPLIT_DIR"
awk -v dir="$CA_SPLIT_DIR" '/-----BEGIN CERTIFICATE-----/ { n++ } n { print > (dir "/ca-" (n - 1) ".pem") }' "$CA_CHAIN_PEM"
ls "$CA_SPLIT_DIR"/ca-*.pem >/dev/null 2>&1 || die "no certificates found in $CA_CHAIN_PEM"

# No intermediate from the endpoint (or an older --from-dir run): use the chain entry that issued the cert.
if [[ ! -s "$INTERMEDIATE_PEM" ]]; then
  ISSUER="$(openssl x509 -in "$CERT_PEM" -noout -issuer -nameopt RFC2253 | sed 's/^issuer=//')"
  for ca in "$CA_SPLIT_DIR"/ca-*.pem; do
    if [[ "$(openssl x509 -in "$ca" -noout -subject -nameopt RFC2253 | sed 's/^subject=//')" == "$ISSUER" ]]; then
      cp "$ca" "$INTERMEDIATE_PEM"
      break
    fi
  done
  [[ -s "$INTERMEDIATE_PEM" ]] || die "the certificate's issuer ($ISSUER) is not in the CA chain"
fi

# ---- checks: the same ones the application makes, so it does not reject what we write -----------------
openssl x509 -in "$CERT_PEM" -noout -pubkey | cmp -s - <(openssl pkey -in "$OUT_DIR/private-key.pem" -pubout) ||
  die "certificate does not match the private key"
openssl verify -partial_chain -CAfile "$INTERMEDIATE_PEM" "$CERT_PEM" >/dev/null 2>&1 ||
  echo "WARNING: the certificate does not verify against intermediate-ca.pem; renewed certificates are checked against it" >&2
openssl x509 -in "$CERT_PEM" -noout -checkend 0 >/dev/null || die "the certificate has already expired"

# ---- passwords: reuse what Vault holds, so stores already written by the application stay readable -----
random_password() { openssl rand -base64 24; } # same length as KeyStoreSyncServiceImpl.generateSecurePassword
if [[ "$NO_VAULT" != "1" ]]; then
  [[ -n "$KEYSTORE_PASSWORD" ]] || KEYSTORE_PASSWORD="$(kv_get keystore-password password)"
  [[ -n "$TRUSTSTORE_PASSWORD" ]] || TRUSTSTORE_PASSWORD="$(kv_get truststore-password password)"
fi
if [[ -z "$KEYSTORE_PASSWORD" && -s "$OUT_DIR/keystore.password" ]]; then KEYSTORE_PASSWORD="$(cat "$OUT_DIR/keystore.password")"; fi
if [[ -z "$TRUSTSTORE_PASSWORD" && -s "$OUT_DIR/truststore.password" ]]; then TRUSTSTORE_PASSWORD="$(cat "$OUT_DIR/truststore.password")"; fi
KEYSTORE_PASSWORD="${KEYSTORE_PASSWORD:-$(random_password)}"
TRUSTSTORE_PASSWORD="${TRUSTSTORE_PASSWORD:-$(random_password)}"
printf '%s' "$KEYSTORE_PASSWORD" >"$OUT_DIR/keystore.password"
printf '%s' "$TRUSTSTORE_PASSWORD" >"$OUT_DIR/truststore.password"

# ---- local stores (the same content the sync job builds) --------------------------------------------
echo "Building keystore.p12 and truststore.p12 in $OUT_DIR ..."
openssl pkcs12 -export \
  -inkey "$OUT_DIR/private-key.pem" -in "$CERT_PEM" -certfile "$CA_CHAIN_PEM" \
  -name "$KEY_ALIAS" -out "$OUT_DIR/keystore.p12" -passout "pass:$KEYSTORE_PASSWORD" ||
  die "could not build keystore.p12"
rm -f "$OUT_DIR/truststore.p12"
if command -v keytool >/dev/null 2>&1; then
  for ca in "$CA_SPLIT_DIR"/ca-*.pem; do
    keytool -importcert -noprompt -storetype PKCS12 -keystore "$OUT_DIR/truststore.p12" -storepass "$TRUSTSTORE_PASSWORD" \
      -alias "$(basename "$ca" .pem)" -file "$ca" >/dev/null 2>&1 || die "could not add $ca to truststore.p12"
  done
elif openssl pkcs12 -help 2>&1 | grep -q -- '-jdktrust'; then
  openssl pkcs12 -export -nokeys -in "$CA_CHAIN_PEM" -jdktrust anyExtendedKeyUsage \
    -out "$OUT_DIR/truststore.p12" -passout "pass:$TRUSTSTORE_PASSWORD" || die "could not build truststore.p12"
else
  echo "WARNING: neither keytool nor openssl 3.2+ found; truststore.p12 not built (the sync job builds it from Vault)" >&2
fi
rm -rf "$CA_SPLIT_DIR"

# ---- Vault ------------------------------------------------------------------------------------------
if [[ "$NO_VAULT" == "1" ]]; then
  echo
  echo "Done (--no-vault). Push this material later with: $0 --from-dir $OUT_DIR"
  exit 0
fi

echo "Writing secrets to Vault ..."
# Key pair and certificate first, together: the application skips the keystore while they do not match.
kv_put keypair "$(jq -n --rawfile pub "$OUT_DIR/public-key.pem" --rawfile priv "$OUT_DIR/private-key.pem" \
  '{publicKey: $pub, privateKey: $priv}')"
kv_put certificate "$(jq -n --rawfile c "$CERT_PEM" '{certificate: $c}')"
kv_put ca-chain "$(jq -n --rawfile c "$CA_CHAIN_PEM" '{chain: $c}')"
kv_put intermediate-ca "$(jq -n --rawfile c "$INTERMEDIATE_PEM" '{certificate: $c}')"
kv_put keystore-password "$(jq -n --arg p "$KEYSTORE_PASSWORD" '{password: $p}')"
kv_put truststore-password "$(jq -n --arg p "$TRUSTSTORE_PASSWORD" '{password: $p}')"

# Read one back to confirm the write landed where the application looks.
[[ "$(kv_get certificate certificate)" == "$(cat "$CERT_PEM")" ]] || die "read-back of the certificate from Vault did not match"

echo
echo "Done. Vault is ready for the certificate manager."
echo "  subject   : $(openssl x509 -in "$CERT_PEM" -noout -subject -nameopt RFC2253 | sed 's/^subject=//')"
echo "  expires   : $(openssl x509 -in "$CERT_PEM" -noout -enddate | sed 's/^notAfter=//')"
echo "  vault     : $VAULT_ADDR  $VAULT_MOUNT/${VAULT_BASE:+$VAULT_BASE/}{keypair,certificate,ca-chain,intermediate-ca,keystore-password,truststore-password}"
echo "  set       : application.vault.secret-path=$VAULT_SECRET_PATH  (VAULT_SECRET_PATH)"
echo "  files     : $OUT_DIR  (holds the private key; keep it private)"
