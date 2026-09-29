# Security & mTLS

This document describes the security architecture of the Federator Certificate Manager, including mutual TLS (mTLS) configuration, OAuth2 client credentials flow, and token caching.

---

## Security Overview

```mermaid
graph TB
    subgraph "Certificate Manager"
        RC["RestClientConfig<br/>(mTLS SSLContext)"]
        OTS["OAuth2TokenService"]
        TCS["TokenCacheService<br/>(Caffeine)"]
        MNS["ManagementNodeService"]
    end

    subgraph "Client Credentials"
        JKS_KS["keystore.jks<br/>(client private key + cert)"]
        JKS_TS["truststore.jks<br/>(trusted CA certs)"]
    end

    subgraph "External Services"
        IDP["OAuth2 IdP<br/>(Keycloak)"]
        MN["Management Node"]
        VAULT["HashiCorp Vault"]
    end

    JKS_KS --> RC
    JKS_TS --> RC
    RC --> OTS
    RC --> MNS
    OTS -- "mTLS + client_credentials" --> IDP
    IDP -- "JWT access_token" --> TCS
    TCS -- "Bearer token" --> MNS
    MNS -- "mTLS + Bearer" --> MN
    RC -.->|"Note: Vault uses<br/>token auth, not mTLS"| VAULT
```

---

## Mutual TLS (mTLS)

All outbound HTTP calls to the Management Node and OAuth2 IdP are secured with mutual TLS. The service presents a client certificate and validates the server's certificate chain.

### How It Works

```mermaid
sequenceDiagram
    participant CM as Certificate Manager
    participant Server as Management Node / IdP

    CM->>Server: TLS ClientHello
    Server-->>CM: TLS ServerHello + Server Certificate
    CM->>CM: Validate server cert against truststore.jks
    Server->>CM: CertificateRequest
    CM-->>Server: Client Certificate (from keystore.jks)
    Server->>Server: Validate client cert
    Note over CM,Server: TLS handshake complete (mutual authentication)
    CM->>Server: HTTP request (encrypted)
    Server-->>CM: HTTP response (encrypted)
```

### Configuration

The mTLS `SSLContext` is built in `RestClientConfig`:

1. **Load client keystore** — Contains the client's private key and X.509 certificate
2. **Load truststore** — Contains CA certificates trusted by the client
3. **Build SSLContext** — Apache `SSLContextBuilder` with both key and trust material
4. **Configure HttpClient** — Apache HttpClient 5 with:
   - `DefaultClientTlsStrategy` using the SSLContext
   - Connection pool with timeout settings
   - Expired connection eviction

```yaml
application:
  client:
    key-store: /etc/certs/keystore.jks        # Client identity
    key-store-password: ${KEYSTORE_PASSWORD}
    trust-store: /etc/certs/truststore.jks     # Trusted CAs
    trust-store-password: ${TRUSTSTORE_PASSWORD}
    key-store-type: JKS                        # JKS or PKCS12
```

### Important Distinction

There are **two sets of keystores** in this system:

| Keystore | Format | Purpose | Managed By |
|----------|--------|---------|------------|
| **Input** keystore.jks / truststore.jks | JKS | mTLS client identity for outbound calls | Operator (pre-provisioned) |
| **Output** keystore.p12 / truststore.p12 | PKCS#12 | Generated certificates for federator services | Certificate Manager (automated) |

The input keystores authenticate the Certificate Manager itself. The output keystores are the product of the certificate lifecycle management.

---

## OAuth2 Client Credentials Flow

The service authenticates with the Management Node API using OAuth2 Bearer tokens obtained via the client credentials grant.

### Token Acquisition Sequence

```mermaid
sequenceDiagram
    participant MNS as ManagementNodeService
    participant TCS as TokenCacheService
    participant OTS as OAuth2TokenService
    participant IdP as OAuth2 IdP

    MNS->>TCS: getToken()

    alt Token cached and valid (> 5 min remaining)
        TCS-->>MNS: cached JWT string
    else Token missing or expiring within 5 min
        TCS->>OTS: getAccessToken()
        OTS->>IdP: POST /token<br/>grant_type=client_credentials<br/>client_id=MANAGEMENT_NODE_CLIENT
        Note over OTS,IdP: Request sent over mTLS
        IdP-->>OTS: { "access_token": "eyJ...", "expires_in": 3600 }
        OTS-->>TCS: TokenResponse
        TCS->>TCS: Cache token (key: "currentToken")
        TCS-->>MNS: JWT string
    end

    MNS->>MNS: Set header: Authorization: Bearer eyJ...
```

### Token Request Details

| Field | Value |
|-------|-------|
| **Method** | `POST` |
| **URL** | Configured `token-uri` |
| **Content-Type** | `application/x-www-form-urlencoded` |
| **grant_type** | `client_credentials` |
| **client_id** | Configured `client-id` |
| **Transport** | mTLS (client certificate used for client authentication) |

> The client authenticates using mTLS (the TLS client certificate) rather than a `client_secret`. This is the `tls_client_auth` method in OAuth2 terminology.

### Token Response

```json
{
  "access_token": "eyJhbGciOiJSUzI1NiIs...",
  "expires_in": 3600,
  "token_type": "Bearer"
}
```

The `TokenResponse` record captures:
- `accessToken` — The JWT string
- `expiresIn` — Seconds until expiry
- `expiryInstant` — Computed as `Instant.now() + expiresIn`

---

## Token Caching

Tokens are cached using Caffeine to avoid unnecessary IdP calls.

### Cache Configuration

| Parameter | Value | Description |
|-----------|-------|-------------|
| **Cache name** | `tokenCache` | Caffeine cache instance |
| **Expiry after write** | 1 hour | Maximum TTL regardless of access pattern |
| **Maximum size** | 10 entries | Upper bound (only 1 entry used in practice) |
| **Cache key** | `"currentToken"` | Fixed key for the single cached token |

### Early Refresh Logic

```mermaid
flowchart TD
    A[getToken called] --> B{Cached token exists?}
    B -- No --> C[Call refreshToken]
    B -- Yes --> D{Expires within 300s?}
    D -- Yes --> C
    D -- No --> E[Return cached token]
    C --> F[OAuth2TokenService.getAccessToken]
    F --> G{Success?}
    G -- Yes --> H[Store in cache]
    H --> I[Return new token]
    G -- No --> J[Evict cache entry]
    J --> K[Throw OAuth2TokenException]
```

The `refreshToken()` method is `synchronized` to prevent multiple concurrent threads from requesting tokens simultaneously.

### Cache Eviction on Failure

If token acquisition fails, the cached entry is evicted (`cacheManager.getCache("tokenCache").evict("currentToken")`) so the next call attempts a fresh request rather than returning a stale/expired token.

---

## Management Node API Authentication

Both Management Node API calls carry the OAuth2 Bearer token:

### GET Intermediate Certificate

```http
GET /api/v1/certificate/intermediate HTTP/1.1
Host: management-node.example.com:8090
Authorization: Bearer eyJhbGciOiJSUzI1NiIs...
```

### POST Sign CSR

```http
POST /api/v1/certificate/csr/sign HTTP/1.1
Host: management-node.example.com:8090
Authorization: Bearer eyJhbGciOiJSUzI1NiIs...
Content-Type: application/json

{
  "csr": "-----BEGIN CERTIFICATE REQUEST-----\nMIIC..."
}
```

---

## Certificate Verification

After receiving a signed certificate from the Management Node, the service verifies it before persistence:

```mermaid
flowchart TD
    A[Receive signed certificate] --> B[Parse leaf cert X.509]
    B --> C[Parse intermediate CA X.509]
    C --> D{cert.checkValidity at current time}
    D -- Invalid --> E[Throw PkiException]
    D -- Valid --> F{cert.verify using CA public key}
    F -- Failed --> G[Throw PkiException]
    F -- Passed --> H[Extract and log issuer CN]
    H --> I[Certificate verified]
```

This ensures the Management Node returned a certificate that:
1. Is currently within its validity period (`notBefore` ≤ now ≤ `notAfter`)
2. Was signed by the expected intermediate CA

---

## Vault Authentication

Vault uses **token-based authentication** (not mTLS). The token is provided via configuration:

```yaml
spring:
  cloud:
    vault:
      token: ${VAULT_TOKEN}
```

For production, consider:
- **AppRole authentication** — Machine-to-machine auth with role_id and secret_id
- **Kubernetes authentication** — Service account token-based auth for K8s deployments
- **Token renewal** — Ensure the Vault token TTL exceeds the application lifecycle or configure auto-renewal

---

## Security Considerations

### Secret Handling

| Secret | Storage | Rotation |
|--------|---------|----------|
| Vault token | Environment variable | Manual or via Vault auth method |
| mTLS keystore password | application.yml or env var | Manual |
| Generated keystore passwords | Vault KV v2 | Automatic (on first creation) |
| Private keys | Vault KV v2 (in memory during operation) | Automatic (on certificate renewal) |

### Filesystem Security

The generated PKCS#12 files and password files should be protected:

```sh
# Restrict access to the secrets directory
chmod 700 /etc/federator/secrets/
chmod 600 /etc/federator/secrets/*
chown app-user:app-group /etc/federator/secrets/*
```

### Network Security

- All Management Node and IdP communication uses mTLS (mutual authentication)
- Vault communication should use HTTPS in production (configure `spring.cloud.vault.ssl.*`)
- No inbound network listeners — the application does not expose any HTTP endpoints

© Crown Copyright 2026. This work has been developed by the National Digital Twin Programme and is legally attributed to the UK's Department for Business, Innovation, Science and Trade (BIST) as the governing entity.
  
Licensed under the Open Government Licence v3.0.  