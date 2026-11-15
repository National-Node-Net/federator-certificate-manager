# bootstrap-vault.sh

Prepares Vault so the certificate manager can start for the first time.

The application needs a certificate and key in Vault before it can call the Management Node.
This script gets a **bootstrap certificate** from the Management Node and writes it, with
everything else the application reads at start-up, to Vault. Run it once, before the first boot.

After that the application handles everything itself: on its first renewal run it sees the
bootstrap certificate and swaps it for a regular one, and the sync job writes the keystore and
truststore files.

## How to run it

Run all commands from the repository root. The script works the same way everywhere; only the
values change (see [Examples](#examples) for the local stack and AWS).

**1. Check the [prerequisites](#before-you-run-it).** In particular, the client certificate must be
in date and trusted by the IDP and the Management Node:

```bash
openssl x509 -in "$CERT_DIR_DEFAULT/client-org1.crt" -noout -subject -issuer -enddate
```

**2. Point the script at your certificates.** At minimum, the folder holding the client certificate
and key, and the CA that signed the servers' certificates:

```bash
export CERT_DIR_DEFAULT='<folder with client-org1.crt and client-org1.key>'
export CA_CERT='<path to rootCA.crt>'
# ...plus any variable below whose default doesn't fit your environment
```

**3. Do a trial run without Vault.** This issues the certificate and writes the files only, so you
can check the IDP, the Management Node and your certificates before touching Vault:

```bash
bash scripts/bootstrap-vault.sh --no-vault --out ./bootstrap-vault-trial
```

It should finish with the files listed under [Output files](#output-files). If it fails, see
[Troubleshooting](#troubleshooting).

**4. Write to Vault.** Push the files from the trial run, so no second certificate is issued:

```bash
export VAULT_TOKEN='<Vault token>'
bash scripts/bootstrap-vault.sh --from-dir ./bootstrap-vault-trial
```

(Or skip step 3 and run `bash scripts/bootstrap-vault.sh` to issue and write in one go.)

**5. Check Vault and tidy up.**

```bash
vault kv list "$VAULT_SECRET_PATH"     # should list the six secrets below
rm -rf ./bootstrap-vault-trial          # it holds a private key
```

**6. Start the application.**

## Variables

The URLs, client and CSR defaults match the local developer stack (`application-dev.yml`). The
certificate paths (`CERT_DIR_DEFAULT`, `CA_CERT`) have no useful default; always set them. Each
variable can also be passed as the option in the last column.

| Variable | Default | What it is | Option |
|---|---|---|---|
| `VAULT_ADDR` | `http://localhost:8200` | Vault address | `--vault-addr` |
| `VAULT_TOKEN` | *(required)* | Vault token; needs read on `sys/mounts` and write under the secret path | `--vault-token` |
| `VAULT_SECRET_PATH` | `node-net/client` | Where the secrets go; must equal the app's `application.vault.secret-path` | `--vault-path` |
| `VAULT_CACERT` | *(none)* | CA for Vault's HTTPS certificate, if it's private | `--vault-cacert` |
| `IDP_URL` | `https://localhost:8443/realms/mng-node/protocol/openid-connect/token` | IDP token endpoint | `--idp-url` |
| `MN_URL` | `https://localhost:8090` | Management Node base URL | `--mn-url` |
| `CLIENT_ID` | `FEDERATOR_ENV` | Keycloak client; must match the app's `application.oauth2.client-id` | `--client-id` |
| `CERT_DIR_DEFAULT` | `/tmp` | Directory holding the client certificate and key; used to build the `CLIENT_CERT` and `CLIENT_KEY` defaults | *(none)* |
| `CLIENT_CERT` | `$CERT_DIR_DEFAULT/client-org1.crt` | Client certificate for mTLS | `--cert` |
| `CLIENT_KEY` | `$CERT_DIR_DEFAULT/client-org1.key` | Client private key for mTLS | `--key` |
| `CA_CERT` | `/rootCA.crt` | Extra CA to trust for the IDP and Management Node | `--cacert` |
| `ORGANISATION_ID` | `2` | Organisation the certificate is issued for | `--org-id` |

Set `CERT_DIR_DEFAULT` to the folder that holds `client-org1.crt` and `client-org1.key`, for example
the dev IDP certs in `ndtp-application-continuous-delivery`
(`applications/environments/dev/ia-node/workload/core/5-management-node/idp/certs`). Setting
`CLIENT_CERT` or `CLIENT_KEY` (or `--cert` / `--key`) overrides the individual file, which is how
you use a certificate with a different name.

**About `CA_CERT`:** the script trusts this CA *in addition to* the system CAs. So the same
`rootCA.crt` works everywhere: servers signed by the private NDTP root CA verify against it, and
servers with public certificates verify against the system CAs.

The certificate subject and SANs (`CSR_CN`, `CSR_O`, `CSR_OU`, `CSR_C`, `CSR_SANS`), key size
(`CSR_KEY_SIZE`) and keystore alias (`KEY_ALIAS`) default to the values in `application-dev.yml`.
Set them to match the app's `CERT_SUBJECT_*`, `CERT_KEY_SIZE` and keystore alias if those differ.
`bash scripts/bootstrap-vault.sh --help` lists everything.

## Examples

**Local developer stack:** the URLs and client defaults fit; set the certificates and the token.

The local Keycloak and Management Node only accept client certificates signed by the NDTP root CA
(`ndtp.co.uk`), so `client-org1` is rejected unless you have added `client-rootCA.crt` to their
truststores (see [Before you run it](#before-you-run-it)). Use the local stack's own client
certificate from the management-node repository instead:

```bash
export CERT_DIR_DEFAULT='<management-node>/docker/cert'
export CLIENT_CERT="$CERT_DIR_DEFAULT/client.crt"   # not named client-org1, so set it explicitly
export CLIENT_KEY="$CERT_DIR_DEFAULT/client.key"
export CA_CERT='<management-node>/docker/compose/rootCA.crt'

bash scripts/bootstrap-vault.sh --no-vault --out ./bootstrap-vault-trial   # trial run

export VAULT_TOKEN='<spring.cloud.vault.token from application-dev.yml>'
bash scripts/bootstrap-vault.sh --from-dir ./bootstrap-vault-trial
```

**AWS (deployed dev environment):** the same steps, with that environment's values. The AWS
environment trusts `client-org1`, so the dev IDP certs folder works as it is.

```bash
export CERT_DIR_DEFAULT='<ndtp-application-continuous-delivery>/applications/environments/dev/ia-node/workload/core/5-management-node/idp/certs'
export CA_CERT='<management-node>/docker/compose/rootCA.crt'
export VAULT_ADDR='https://<deployed Vault>'
export VAULT_TOKEN="$(vault print token)"        # after `vault login`
export VAULT_SECRET_PATH='<app VAULT_SECRET_PATH>'
export IDP_URL='https://ia-idp.dev.ndtp.co.uk/realms/mng-node/protocol/openid-connect/token'
export MN_URL='https://ia-management-node.dev.ndtp.co.uk:443'
export CLIENT_ID='FEDERATOR_BCC'
export ORGANISATION_ID='<organisation id>'

bash scripts/bootstrap-vault.sh --no-vault --out ./bootstrap-vault-trial   # trial run
bash scripts/bootstrap-vault.sh --from-dir ./bootstrap-vault-trial
```

If Vault is only reachable inside the cluster, port-forward it first
(`kubectl -n <namespace> port-forward svc/vault 8200:8200`) and use that address.

## Before you run it

- **Tools:** `curl`, `jq`, `unzip`, `openssl`, and a JDK (`keytool`).
- **Vault** reachable, with a KV v2 mount at the first segment of `VAULT_SECRET_PATH`
  (`--create-mount` creates it if missing).
- **The IDP and Management Node** reachable. For AWS that means the VPN.
- **Your client certificate is in date.** Check with `openssl x509 -in <cert> -noout -enddate`.
  Older copies of `client-org1.crt` (e.g. in personal backup folders) expired on 23 Aug 2026; use
  the one in the dev IDP certs folder, or renew it with `renew-client-cert.sh` in that folder.
- **The servers trust your client certificate.** `client-org1` is signed by `client-rootCA.crt`
  (in the same folder). The AWS environment already trusts it. The local stack trusts only the
  NDTP root CA: either use the local `client.crt` (see [Examples](#examples)), or add
  `client-rootCA.crt` to the Keycloak and Management Node truststores and restart them. To see
  which client CAs a server accepts:
  `openssl s_client -connect localhost:8443 </dev/null 2>/dev/null | grep -A3 "Acceptable client"`
- **The Keycloak client** (`CLIENT_ID`) has the roles `create_keys`,
  `request_bootstrap_certificate` and `access_public_certificates`.

> Each run issues a real certificate on the Management Node. Run it only when you mean to.

## What it does

1. Checks Vault: token valid, mount exists, no certificate there yet (unless `--force`)
2. Gets an OAuth token from the IDP (mTLS, `client_credentials`)
3. Asks the Management Node for a key pair and creates a CSR from it
4. Requests a bootstrap certificate for the organisation
5. Fetches the intermediate CA
6. Checks the certificate: matches the key, verifies against the CA, not expired
7. Writes the secrets to Vault and reads one back to confirm

Vault is checked first, so a wrong token or path doesn't waste a certificate.

## What ends up in Vault

Under `VAULT_SECRET_PATH`:

| Secret | Fields |
|---|---|
| `keypair` | `publicKey`, `privateKey` |
| `certificate` | `certificate` |
| `ca-chain` | `chain` |
| `intermediate-ca` | `certificate` |
| `keystore-password` | `password` |
| `truststore-password` | `password` |

Existing password secrets are reused, so stores the application has already written stay readable.

```bash
vault kv list node-net/client
```

## Output files

Written to `./bootstrap-vault-<timestamp>/` (gitignored), or `--out <dir>` (`OUT_DIR`): the PEM files
(key pair, CSR, certificate, CA chain, intermediate CA) and a `keystore.p12` / `truststore.p12`
with their `.password` files. The folder holds a private key; delete it when you're done.

## Other options

| Option | Use it when |
|---|---|
| `--force` (`FORCE=1`) | Vault already has a certificate and you want to replace it |
| `--create-mount` | The KV mount doesn't exist yet |
| `--no-vault` | Issue the certificate and write files only |
| `--from-dir <dir>` | Push an earlier run's files to Vault without issuing a new certificate |
| `--out <dir>` | Put the output files somewhere else |
| `--insecure` | Quick test only: skips all server certificate checks |

## Troubleshooting

| Message | Cause and fix |
|---|---|
| `a certificate already exists at ...` | Vault is already set up. Nothing to do, or pass `--force` |
| `VAULT_TOKEN (or --vault-token) is required` | Export `VAULT_TOKEN` |
| `Vault token is not valid` | Wrong or expired token |
| `KV mount '...' not found` | `vault secrets enable -path=<mount> kv-v2`, or pass `--create-mount` |
| `CA certificate not readable` | `CA_CERT` points at a file that isn't there |
| `curl: (60) SSL certificate problem` | The server's CA is neither a system CA nor `CA_CERT`; point `CA_CERT` at it |
| `sslv3 alert certificate unknown` at step 1 | The server doesn't trust your client certificate. Locally, use the local `client.crt` or add `client-rootCA.crt` to the server's truststore (see [Before you run it](#before-you-run-it)) |
| `sslv3 alert certificate expired` | The client certificate has expired; check `-enddate` and use or renew a current one |
| `client certificate not readable` | `CERT_DIR_DEFAULT` / `CLIENT_CERT` points at a missing file; the file must be named `client-org1.crt` unless you set `CLIENT_CERT` |
| Hangs at step 1 | The IDP isn't reachable (VPN for AWS) |
| `HTTP 401` at step 1 | `CLIENT_ID` doesn't match the certificate, or the client needs `--client-secret` |
| `HTTP 403` | The Keycloak client is missing a role |
| `/intermediate returned HTTP 403` | Not fatal; the issuer from the CA chain is used. Add `access_public_certificates` to avoid it |
