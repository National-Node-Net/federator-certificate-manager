## Overview

The Federator Certificate Manager is a non-interactive Spring Boot service that automates X.509 certificate lifecycle management for federator components within the **National Digital Twin Programme (NDTP)**. It operates as a headless daemon — no HTTP endpoints are exposed — running two scheduled jobs that handle certificate renewal and filesystem synchronisation.

The service integrates with **HashiCorp Vault** (KV v2) for secret persistence, an external **Management Node** API for PKI operations (intermediate CA retrieval and CSR signing), and an **OAuth2 Identity Provider** for token-based authentication. All external HTTP communication is secured via mutual TLS (mTLS).

---

## Prerequisites

| Dependency | Version | Purpose |
|------------|---------|---------|
| **JDK** | 21+ | Runtime and compilation |
| **Apache Maven** | 3.9+ | Build tool |
| **HashiCorp Vault** | 1.15+ | Secret storage (KV v2 engine) |
| **Management Node** | — | External PKI API (intermediate CA, CSR signing) |
| **OAuth2 IdP** | — | Identity Provider (e.g., Keycloak) for client credentials |
| **JKS Keystores** | — | Client keystore and truststore for mTLS |

### System Requirements

- **OS:** Linux, macOS, or Windows with Java 21+
- **Memory:** 256 MB minimum heap (512 MB recommended)
- **Disk:** Writable path for PKCS#12 output files
- **Network:** Outbound HTTPS to Vault, Management Node, and IdP

---

## Features

- **Automated Certificate Renewal** — Monitors certificate validity against a configurable threshold and triggers renewal when approaching expiry
- **Intermediate CA Management** — Automatically fetches and refreshes the intermediate CA from the Management Node before it expires
- **PKCS#12 KeyStore/TrustStore Generation** — Produces `keystore.p12` and `truststore.p12` from PEM artifacts stored in Vault
- **Atomic Filesystem Writes** — Uses temp-file-then-rename to prevent partial writes on crash
- **HashiCorp Vault Integration** — Persists all cryptographic material (key pairs, certificates, CA chains, passwords) to Vault KV v2
- **mTLS-Secured Communication** — All outbound HTTP calls use mutual TLS with configurable JKS keystores
- **OAuth2 Client Credentials Flow** — Authenticates against an IdP with Caffeine-cached tokens and automatic refresh
- **SBOM Generation** — CycloneDX Maven plugin produces a Software Bill of Materials at build time

---

## Architecture

For detailed architecture documentation including C4 diagrams, sequence diagrams, and component descriptions, see:

| Document | Description |
|----------|-------------|
| [Architecture Overview](docs/architecture.md) | C4 context, container, and component diagrams |
| [Certificate Lifecycle](docs/certificate-lifecycle.md) | Renewal and sync workflows with sequence diagrams |
| [Configuration Reference](docs/configuration.md) | All `application.yml` properties with descriptions |
| [Vault Integration](docs/vault-integration.md) | Vault KV v2 secret paths and operations |
| [Security & mTLS](docs/security.md) | OAuth2 flow, mTLS setup, and token caching |

---

## Quick Start

### 1. Clone and Build

```sh
git clone git@github.com:National-Node-Net/federator-certificate-manager.git
cd federator-certificate-manager
mvn clean package -DskipTests
```

### 2. Verify Build

```sh
java -jar target/federator-certificate-manager-1.0.1.jar --version
```

### 3. Run Tests

```sh
# All tests
mvn test

# Specific test class
mvn test -Dtest=CertificateManagerServiceImplTest

# With coverage report
mvn verify
```

### 4. Code Formatting

```sh
# Check formatting (Palantir Java Format via Spotless)
mvn spotless:check

# Auto-fix formatting
mvn spotless:apply
```

---

## Installation

> **Running locally with management-node?** Skip to [Local Development with Management Node](#local-development-with-management-node) for a streamlined setup.

### Step 1: Provision HashiCorp Vault

Enable a KV v2 secrets engine at the mount path matching your configuration:

```sh
vault secrets enable -path=pki-client kv-v2
```

Ensure the application's Vault token has read/write access to the configured secret path:

```hcl
path "pki-client/data/node-net/client/*" {
  capabilities = ["create", "read", "update", "delete", "list"]
}

path "pki-client/metadata/node-net/client/*" {
  capabilities = ["read", "list"]
}

path "sys/mounts" {
  capabilities = ["read"]
}
```

### Step 2: Prepare mTLS Keystores

The service requires a JKS keystore (containing the client private key and certificate) and a JKS truststore (containing trusted CA certificates) for mTLS communication with the Management Node and IdP.

```sh
# Example: Create a client keystore
keytool -genkeypair -alias client -keyalg RSA -keysize 2048 \
  -keystore keystore.jks -storepass changeit \
  -dname "CN=certificate-manager,O=NDTP,C=GB"

# Example: Import CA certificate into truststore
keytool -importcert -alias ca -file ca-cert.pem \
  -keystore truststore.jks -storepass changeit -noprompt
```

To simulate starting from a bootstrap certificate, run the following command to provision a certificate with a short expiry window:
```
make bootstrap-test-certs-clean
```

If running in tandem with management node and IdP, this script will import the CA certificate to ensure trusted communication between components. The location of this certificate can be set within the `Makefile` in the `ROOT_CA_DIR` variable.

### Step 3: Configure the Application

Every property in `application.yml` is backed by an environment variable with a sensible default. You can override any value by setting the corresponding environment variable — no YAML editing required.

See the [Configuration Reference](docs/configuration.md) for full details.

#### Vault & Infrastructure

| Environment Variable | Property Path | Default | Description |
|---|---|---|---|
| `VAULT_URI` | `spring.cloud.vault.uri` | `http://localhost:8200` | Vault server URI |
| `VAULT_TOKEN` | `spring.cloud.vault.token` | _(empty)_ | Vault authentication token |
| `VAULT_PKI_MOUNT` | `application.vault.pki-mount` | `pki-client` | KV v2 mount path in Vault |
| `VAULT_SECRET_PATH` | `application.vault.secret-path` | `node-net/client` | Base relative path for secrets under the mount |

#### mTLS Client

| Environment Variable | Property Path | Default | Description |
|---|---|---|---|
| `MTLS_KEYSTORE_PATH` | `application.client.key-store` | `...docker/keystore.jks` | Path to JKS keystore (client private key + cert) |
| `MTLS_KEYSTORE_PASSWORD` | `application.client.key-store-password` | `changeit` | Keystore password |
| `MTLS_TRUSTSTORE_PATH` | `application.client.trust-store` | `...docker/truststore.jks` | Path to JKS truststore (trusted CAs) |
| `MTLS_TRUSTSTORE_PASSWORD` | `application.client.trust-store-password` | `changeit` | Truststore password |
| `MTLS_KEYSTORE_TYPE` | `application.client.key-store-type` | `JKS` | Keystore format (`JKS` or `PKCS12`) |

#### OAuth2 & Management Node

| Environment Variable | Property Path | Default | Description |
|---|---|---|---|
| `OAUTH2_TOKEN_URI` | `application.oauth2.token-uri` | `https://localhost:8443/realms/mng-node/protocol/openid-connect/token` | OAuth2 token endpoint |
| `OAUTH2_CLIENT_ID` | `application.oauth2.client-id` | `MANAGEMENT_NODE_CLIENT` | OAuth2 client ID for client credentials grant |
| `MANAGEMENT_NODE_BASE_URL` | `application.management-node.base-url` | `https://localhost:8090` | Management Node API base URL |

#### Scheduling

| Environment Variable | Property Path | Default | Description |
|---|---|---|---|
| `CERT_RENEWAL_RATE` | `application.scheduling.certificate-manager.renewal-rate` | `3600000` | Renewal job interval in ms (default: 1 hour) |
| `CERT_SYNC_RATE` | `application.scheduling.certificate-manager.sync-rate` | `60000` | Sync job interval in ms (default: 1 minute) |

#### Certificate Properties

| Environment Variable | Property Path | Default | Description |
|---|---|---|---|
| `CERT_RENEWAL_THRESHOLD` | `application.certificate.renewal-threshold-percentage` | `10` | Percentage of validity remaining that triggers renewal |
| `CERT_KEY_SIZE` | `application.certificate.key-size` | `2048` | RSA key size in bits (`2048` or `4096`) |
| `CERT_INTERMEDIATE_MIN_VALID_DAYS` | `application.certificate.intermediate.min-valid-days` | `14` | Minimum days of CA validity before refresh |

#### Certificate Subject

| Environment Variable | Property Path | Default | Description |
|---|---|---|---|
| `CERT_SUBJECT_COUNTRY` | `application.certificate.subject.country` | `UK` | X.500 Country (C) |
| `CERT_SUBJECT_STATE` | `application.certificate.subject.state` | `South Yorkshire` | X.500 State (ST) |
| `CERT_SUBJECT_LOCALITY` | `application.certificate.subject.locality` | `Sheffield` | X.500 Locality (L) |
| `CERT_SUBJECT_ORG` | `application.certificate.subject.organization` | `Acme Digital Solutions Ltd` | X.500 Organization (O) |
| `CERT_SUBJECT_OU` | `application.certificate.subject.organizational-unit` | `Platform Engineering` | X.500 Organizational Unit (OU) |
| `CERT_SUBJECT_CN` | `application.certificate.subject.common-name` | `api.acme-digital.co.uk` | X.500 Common Name (CN) |
| `CERT_SUBJECT_ALT_NAMES` | `application.certificate.subject.alt-names` | `api.acme-digital.co.uk,api.internal.acme-digital.co.uk` | Comma-separated DNS SANs |

#### Output Destination

| Environment Variable | Property Path | Default | Description |
|---|---|---|---|
| `CERT_DEST_PATH` | `application.certificate.destination.path` | `/home/developer/test-secrets/` | Base directory for generated files |
| `CERT_DEST_KEYSTORE_FILE` | `application.certificate.destination.keystore-file` | `keystore.p12` | PKCS#12 keystore filename |
| `CERT_DEST_TRUSTSTORE_FILE` | `application.certificate.destination.truststore-file` | `truststore.p12` | PKCS#12 truststore filename |
| `CERT_DEST_KEYSTORE_PASSWORD_FILE` | `application.certificate.destination.keystore-password-file` | `keystore.password` | Keystore password filename |
| `CERT_DEST_TRUSTSTORE_PASSWORD_FILE` | `application.certificate.destination.truststore-password-file` | `truststore.password` | Truststore password filename |
| `CERT_DEST_KEYSTORE_ALIAS` | `application.certificate.destination.keystore-alias` | `federator` | Private key alias in the keystore |

#### Logging

| Environment Variable | Property Path | Default | Description |
|---|---|---|---|
| `LOG_LEVEL_SPRING_SECURITY` | `logging.level.org.springframework.security` | `DEBUG` | Spring Security log level |
| `LOG_LEVEL_APP` | `logging.level.uk.gov.dbt.ndtp.federator.certificate.manager` | `DEBUG` | Application log level |

### Step 4: Choose a Configuration Strategy

There are two approaches to configuring the application for different environments: **Spring Profiles** and **environment variables**. These can be combined.

#### Option A: Spring Profiles

Create an environment-specific configuration file named `application-{profile}.yml` alongside the default `application.yml` (or in an external config directory). Properties defined in the profile file override the defaults.

For example, to create a `prod` profile, place an `application-prod.yml` in `src/main/resources/` or in an external config location:

```sh
# Activate the profile at runtime
java -jar target/federator-certificate-manager-1.0.1.jar --spring.profiles.active=prod

# Or via environment variable
SPRING_PROFILES_ACTIVE=prod java -jar target/federator-certificate-manager-1.0.1.jar
```

Spring Boot resolves configuration in this order (last wins):
1. `application.yml` — base defaults
2. `application-{profile}.yml` — profile-specific overrides
3. Environment variables — highest precedence

This means a `prod` profile file only needs to contain the properties that differ from the defaults. Everything else is inherited.

#### Option B: Environment Variables Only

Pass environment variables directly — no additional YAML files needed:

```sh
VAULT_URI=https://vault.prod.example.com:8200 \
VAULT_TOKEN=s.xxxxx \
MTLS_KEYSTORE_PATH=/etc/certs/keystore.jks \
MTLS_KEYSTORE_PASSWORD=secret \
MTLS_TRUSTSTORE_PATH=/etc/certs/truststore.jks \
MTLS_TRUSTSTORE_PASSWORD=secret \
OAUTH2_TOKEN_URI=https://idp.prod.example.com/realms/mng-node/protocol/openid-connect/token \
MANAGEMENT_NODE_BASE_URL=https://management-node.prod.example.com:8090 \
CERT_DEST_PATH=/etc/federator/secrets/ \
LOG_LEVEL_APP=INFO \
LOG_LEVEL_SPRING_SECURITY=WARN \
java -jar target/federator-certificate-manager-1.0.1.jar
```

This approach works well for container orchestrators (Docker, Kubernetes) where environment variables are the standard configuration mechanism.

#### Option C: External Config File

Point to a config file outside the JAR:

```sh
java -jar target/federator-certificate-manager-1.0.1.jar \
  --spring.config.location=file:/etc/federator/application.yml
```

### Step 5: Run the Application

```sh
# Using Maven (development)
mvn spring-boot:run

# Using the JAR directly
java -jar target/federator-certificate-manager-1.0.1.jar

# With a Spring profile
java -jar target/federator-certificate-manager-1.0.1.jar --spring.profiles.active=prod
```

### Step 5: Verify Operation

Check the application logs for successful startup:

```
INFO  CertificateRenewalJob - Starting certificate renewal check...
INFO  CertificateManagerServiceImpl - Intermediate CA is valid
INFO  CertificateManagerServiceImpl - Certificate is valid. No renewal needed.
INFO  CertificateSyncJob - Starting certificate sync...
INFO  KeyStoreSyncServiceImpl - Keystore is up to date, skipping write
```

---

## Local Development with Management Node

This section covers running the certificate manager locally alongside the management-node and its Keycloak/Vault infrastructure. It assumes you have already completed the [management-node local setup](https://github.com/National-Node-Net/management-node#readme).

### Prerequisites

- Management Node is running on `https://localhost:8090`
- Keycloak is running on `https://localhost:8443` with the `mng-node` realm configured
- Vault is running on `http://localhost:8200`, initialised and unsealed
- The management-node's Vault PKI engine is configured (see management-node README, Vault Setup section)

### 1. Enable the Vault KV v2 Engine

The certificate manager uses a separate KV v2 engine (not the PKI engine) to store its secrets:

```sh
docker exec -e VAULT_TOKEN=$VAULT_TOKEN vault vault secrets enable -path=pki-client kv-v2
```

### 2. Enable Certificate Automation for the Organisation

The sample data migration sets `certificate_automation_enabled = FALSE` for all organisations. Update the Environment Agency organisation to enable it:

```sh
docker exec -e PGPASSWORD=keycloak_db_user_password keycloak-postgres-1 \
  psql -U keycloak_db_user -d keycloak_db -c \
  "UPDATE mn.organisation SET certificate_automation_enabled = TRUE WHERE id = 1;"
```

### 3. Bootstrap: Get Initial Certificate Material

The certificate manager needs initial certificate material in Vault before it can start. This uses the `management-node` client (which already has `request_bootstrap_certificate` from the management-node setup) to request a bootstrap certificate on behalf of the Environment Agency organisation.

Run from the `management-node/docker` directory:

**a. Generate a key pair for the organisation:**

```sh
openssl genrsa -out env.key 2048
openssl req -new -key env.key -out env.csr -subj "/CN=api.env.gov.uk/O=Environment Agency/C=UK"
```

**b. Get a token and request the bootstrap certificate:**

```sh
TOKEN=$(curl -sk --cert client.crt --key client.key \
  -d "grant_type=client_credentials&client_id=management-node" \
  -d "client_secret=${KEYCLOAK_CLIENT_SECRET}" \
  "https://localhost:8443/realms/mng-node/protocol/openid-connect/token" | jq -r .access_token)

curl -sk --cert client.crt --key client.key \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d "$(jq -n --arg csr "$(cat env.csr)" '{organisationId: 1, csr: $csr}')" \
  "https://localhost:8090/api/v1/certificate/bootstrap" \
  --output bootstrap_bundle.zip

unzip -o bootstrap_bundle.zip
```

This produces `certificate.pem` and `ca-chain.pem`.

**c. Deploy the bootstrap material to Vault:**

```sh
docker exec -e VAULT_TOKEN=$VAULT_TOKEN vault vault kv put pki-client/node-net/client/keypair \
  privateKey="$(cat env.key)" \
  publicKey="$(openssl rsa -in env.key -pubout 2>/dev/null)"

docker exec -e VAULT_TOKEN=$VAULT_TOKEN vault vault kv put pki-client/node-net/client/certificate \
  certificate="$(cat certificate.pem)"

docker exec -e VAULT_TOKEN=$VAULT_TOKEN vault vault kv put pki-client/node-net/client/ca-chain \
  chain="$(cat ca-chain.pem)"
```

### 4. Configure FEDERATOR_ENV for X.509 Authentication

The cert-manager authenticates with Keycloak using its mTLS client certificate, not a client secret. Update the `FEDERATOR_ENV` client in the Keycloak admin console:

1. Navigate to **mng-node realm** → **Clients** → **FEDERATOR_ENV**
2. Go to the **Credentials** tab
3. Change **Client Authenticator** to `X509 Certificate`
4. Set **Subject DN** to `CN=api.env.gov.uk`
6. Save

Then add the certificate roles:

1. Go to the **Service accounts roles** tab
2. Click **Assign role** → filter by **management-node** client
3. Add: `create_keys`, `sign_certificate`, and `access_public_certificates`

> **Note:** The cert-manager must authenticate as `FEDERATOR_ENV` because the management-node maps the JWT's client ID to an organisation via the Producer/Consumer `idpClientId` field. A separate client ID would not resolve to any organisation. In production, each organisation's cert-manager would authenticate as that organisation's client.

### 5. Create `application-local.yml`

Create `src/main/resources/application-local.yml`:

```yaml
spring:
  cloud:
    vault:
      token: <your_vault_root_token>

application:
  vault:
    secret-path: pki-client/node-net/client
  client:
    key-store: /tmp/federator-secrets/keystore.p12
    trust-store: /tmp/federator-secrets/truststore.p12
    key-store-type: PKCS12
  oauth2:
    client-id: FEDERATOR_ENV
  certificate:
    subject:
      common-name: api.env.gov.uk
    destination:
      path: /tmp/federator-secrets/
```

> **Note:** The `key-store` and `trust-store` point at the same destination path where the sync job writes. On startup, the sync job reads the bootstrap material from Vault and creates the initial keystores. The renewal job then uses those keystores for mTLS communication with Keycloak and the management-node. No `client-secret` is needed — the cert-manager authenticates with Keycloak using the X.509 client certificate in the keystore.

### 6. Run

```sh
mvn spring-boot:run -Dspring-boot.run.profiles=local
```

On startup:
1. The **sync job** runs first — reads the bootstrap material from Vault and writes `keystore.p12` and `truststore.p12` to the destination path
2. The **renewal job** runs next — uses those keystores for mTLS, detects the bootstrap certificate (short TTL + bootstrap OID), and triggers automatic renewal

If working correctly, you should see `Bootstrap certificate detected. Initiating immediate renewal...` in the logs.

To observe the renewal cycle more easily during development, you can add shorter intervals to your `application-local.yml`:

```yaml
application:
  scheduling:
    certificate-manager:
      renewal-rate: 60000    # 1 minute
      sync-rate: 30000       # 30 seconds
  certificate:
    renewal-threshold-percentage: 100  # always renew
```

© Crown Copyright 2026. This work has been developed by the National Digital Twin Programme and is legally attributed to the Department for Business and Trade (UK) as the governing entity.

Licensed under the Open Government Licence v3.0.  