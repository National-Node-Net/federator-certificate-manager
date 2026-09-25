# Configuration Reference

All configuration is managed through environment variables with sensible defaults baked into `application.yml`. Every property uses the `${ENV_VAR:default}` pattern — set the environment variable to override, or leave it unset to use the default.

This document covers every configurable property, grouped by domain.

---

## Spring Application Properties

| Property Path | Environment Variable | Default | Description |
|---|---|---|---|
| `spring.main.web-application-type` | — | `none` | Disables the embedded web server — this is a headless service |
| `spring.application.name` | `SPRING_APPLICATION_NAME` | `certificate-manager` | Application name for logging and Vault integration |

---

## Vault Connection

| Property Path | Environment Variable | Default | Required | Description |
|---|---|---|---|---|
| `spring.cloud.vault.uri` | `VAULT_URI` | `http://localhost:8200` | Yes | Vault server URI (HTTP or HTTPS) |
| `spring.cloud.vault.token` | `VAULT_TOKEN` | _(empty)_ | Yes | Vault authentication token |

> **Security Note:** Always pass the Vault token via the `VAULT_TOKEN` environment variable. Never commit tokens to source control.

---

## Application Vault Settings

| Property Path | Environment Variable | Default | Required | Description |
|---|---|---|---|---|
| `application.vault.pki-mount` | `VAULT_PKI_MOUNT` | `pki-client` | Yes | KV v2 mount path in Vault |
| `application.vault.secret-path` | `VAULT_SECRET_PATH` | `node-net/client` | Yes | Base relative path under the mount for all secrets |

Secrets are stored at: `{pki-mount}/data/{secret-path}/{suffix}`

See [Vault Integration](vault-integration.md) for the full secret path reference.

---

## mTLS Client Configuration

| Property Path | Environment Variable | Default | Required | Description |
|---|---|---|---|---|
| `application.client.key-store` | `MTLS_KEYSTORE_PATH` | `...docker/keystore.jks` | Yes | Filesystem path to the JKS keystore containing the client private key and certificate |
| `application.client.key-store-password` | `MTLS_KEYSTORE_PASSWORD` | `changeit` | Yes | Password for the client keystore |
| `application.client.trust-store` | `MTLS_TRUSTSTORE_PATH` | `...docker/truststore.jks` | Yes | Filesystem path to the JKS truststore containing trusted CA certificates |
| `application.client.trust-store-password` | `MTLS_TRUSTSTORE_PASSWORD` | `changeit` | Yes | Password for the truststore |
| `application.client.key-store-type` | `MTLS_KEYSTORE_TYPE` | `JKS` | No | Keystore format (`JKS` or `PKCS12`) |

These keystores are used for **outbound** mTLS connections to the Management Node and OAuth2 IdP. They are separate from the PKCS#12 keystores the service generates.

### HTTP Client Timeouts

Configured in `RestClientConfig` (not externalized):

| Setting | Value | Description |
|---------|-------|-------------|
| Connection timeout | 10 seconds | TCP connection establishment timeout |
| Socket timeout | 30 seconds | Time waiting for data on an established connection |
| Response timeout | 30 seconds | Overall response timeout |

---

## OAuth2 Configuration

| Property Path | Environment Variable | Default | Required | Description |
|---|---|---|---|---|
| `application.oauth2.token-uri` | `OAUTH2_TOKEN_URI` | `https://localhost:8443/realms/mng-node/protocol/openid-connect/token` | Yes | OAuth2 token endpoint URL |
| `application.oauth2.client-id` | `OAUTH2_CLIENT_ID` | `MANAGEMENT_NODE_CLIENT` | Yes | Client ID for the client credentials grant |

### Token Caching

Managed by `TokenCacheServiceImpl` using Caffeine (not externalized):

| Setting | Value | Description |
|---------|-------|-------------|
| Cache name | `tokenCache` | Caffeine cache identifier |
| Expiry after write | 1 hour | Maximum TTL for cached tokens |
| Maximum entries | 10 | Maximum number of cached tokens |
| Early refresh threshold | 300 seconds | Refresh token if it expires within this window |

---

## Management Node Configuration

| Property Path | Environment Variable | Default | Required | Description |
|---|---|---|---|---|
| `application.management-node.base-url` | `MANAGEMENT_NODE_BASE_URL` | `https://localhost:8090` | Yes | Base URL of the Management Node API |

### API Endpoints Used

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/v1/certificate/intermediate` | Retrieve the current intermediate CA certificate |
| `POST` | `/api/v1/certificate/csr/sign` | Submit a CSR for signing and receive the signed certificate |

---

## Scheduling Configuration

| Property Path | Environment Variable | Default | Description |
|---|---|---|---|
| `application.scheduling.certificate-manager.renewal-rate` | `CERT_RENEWAL_RATE` | `3600000` (1 hour) | Fixed delay in milliseconds between renewal job executions |
| `application.scheduling.certificate-manager.sync-rate` | `CERT_SYNC_RATE` | `60000` (1 minute) | Fixed delay in milliseconds between sync job executions |

> **Note:** The scheduler uses a `ThreadPoolTaskScheduler` with a pool size of 2 threads (prefix: `cert-mgr-`).

---

## Certificate Configuration

### Core Properties

| Property Path | Environment Variable | Default | Description |
|---|---|---|---|
| `application.certificate.renewal-threshold-percentage` | `CERT_RENEWAL_THRESHOLD` | `10` | Percentage of total validity period remaining that triggers renewal |
| `application.certificate.key-size` | `CERT_KEY_SIZE` | `2048` | RSA key size in bits (`2048` or `4096`) |
| `application.certificate.bootstrap-oid` | `BOOTSTRAP_OID` | `1.3.6.1.4.1.32473.1.1` | OID used to identify bootstrap certificates via an otherName SAN entry. When detected, the certificate is immediately renewed |
| `application.certificate.intermediate.min-valid-days` | `CERT_INTERMEDIATE_MIN_VALID_DAYS` | `14` | Minimum days of validity for the intermediate CA before refresh |

### Subject Fields

| Property Path | Environment Variable | Default | Description |
|---|---|---|---|
| `application.certificate.subject.country` | `CERT_SUBJECT_COUNTRY` | `UK` | X.500 Country (C) |
| `application.certificate.subject.state` | `CERT_SUBJECT_STATE` | `South Yorkshire` | X.500 State or Province (ST) |
| `application.certificate.subject.locality` | `CERT_SUBJECT_LOCALITY` | `Sheffield` | X.500 Locality (L) |
| `application.certificate.subject.organization` | `CERT_SUBJECT_ORG` | `Acme Digital Solutions Ltd` | X.500 Organization (O) |
| `application.certificate.subject.organizational-unit` | `CERT_SUBJECT_OU` | `Platform Engineering` | X.500 Organizational Unit (OU) |
| `application.certificate.subject.common-name` | `CERT_SUBJECT_CN` | `api.acme-digital.co.uk` | X.500 Common Name (CN) — typically the primary FQDN |
| `application.certificate.subject.alt-names` | `CERT_SUBJECT_ALT_NAMES` | `api.acme-digital.co.uk,api.internal.acme-digital.co.uk` | Comma-separated DNS Subject Alternative Names |

### Destination (Output Files)

| Property Path | Environment Variable | Default | Description |
|---|---|---|---|
| `application.certificate.destination.path` | `CERT_DEST_PATH` | `/home/developer/test-secrets/` | Base directory for output files |
| `application.certificate.destination.keystore-file` | `CERT_DEST_KEYSTORE_FILE` | `keystore.p12` | PKCS#12 keystore filename |
| `application.certificate.destination.truststore-file` | `CERT_DEST_TRUSTSTORE_FILE` | `truststore.p12` | PKCS#12 truststore filename |
| `application.certificate.destination.keystore-password-file` | `CERT_DEST_KEYSTORE_PASSWORD_FILE` | `keystore.password` | Plaintext file containing the keystore password |
| `application.certificate.destination.truststore-password-file` | `CERT_DEST_TRUSTSTORE_PASSWORD_FILE` | `truststore.password` | Plaintext file containing the truststore password |
| `application.certificate.destination.keystore-alias` | `CERT_DEST_KEYSTORE_ALIAS` | `federator` | Alias for the private key entry in the keystore |

> **Password Resolution:** If `keystore-password` or `truststore-password` is not set in the config, the service checks Vault. If not found in Vault, a cryptographically random Base64-encoded 24-byte password is generated and persisted to Vault.

---

## Logging Configuration

| Property Path | Environment Variable | Default | Description |
|---|---|---|---|
| `logging.level.org.springframework.security` | `LOG_LEVEL_SPRING_SECURITY` | `DEBUG` | Spring Security log level |
| `logging.level.uk.gov.dbt.ndtp.federator.certificate.manager` | `LOG_LEVEL_APP` | `DEBUG` | Application log level |

The console and file log patterns are fixed:

```
%d{yyyy-MM-dd HH:mm:ss.SSS} [%thread] %-5level %logger{36} [%X{clientId}] - %msg%n
```

---

## Configuration Precedence

Spring Boot resolves configuration in the following order (last wins):

| Priority | Source | Example |
|----------|--------|---------|
| 1 (lowest) | `application.yml` defaults | Default values after the `:` in `${ENV_VAR:default}` |
| 2 | Profile-specific file | `application-prod.yml` |
| 3 | Environment variables | `VAULT_URI=https://vault.prod:8200` |
| 4 (highest) | Command-line arguments | `--spring.cloud.vault.uri=https://...` |

---

## Spring Profiles

Use profiles to manage environment-specific configuration without modifying the base `application.yml`.

### Creating a Profile

Create `application-{profile}.yml` in `src/main/resources/` or in an external config directory. Only include properties that differ from the defaults:

**Example: `application-prod.yml`** — overrides just the production-specific values while inheriting all other defaults from `application.yml`.

### Activating a Profile

```sh
# Via command-line argument
java -jar federator-certificate-manager-1.0.1.jar --spring.profiles.active=prod

# Via environment variable
SPRING_PROFILES_ACTIVE=prod java -jar federator-certificate-manager-1.0.1.jar

# Multiple profiles (comma-separated, last wins on conflicts)
java -jar federator-certificate-manager-1.0.1.jar --spring.profiles.active=base,prod
```

### Combining Profiles with Environment Variables

Profiles and environment variables can be used together. A common pattern is to use a profile for structural differences (e.g., different logging patterns) and environment variables for secrets and per-instance values:

```sh
SPRING_PROFILES_ACTIVE=prod \
VAULT_TOKEN=s.xxxxx \
MTLS_KEYSTORE_PASSWORD=secret \
java -jar federator-certificate-manager-1.0.1.jar
```

© Crown Copyright 2026. This work has been developed by the National Digital Twin Programme and is legally attributed to the UK's Department for Business, Innovation, Science and Trade (BIST) as the governing entity.
  
Licensed under the Open Government Licence v3.0.  