# Architecture Overview

This document describes the architecture of the Federator Certificate Manager using C4 model diagrams (Context, Container, Component) and explains how the service integrates with external systems.

---

## C4 Level 1: System Context Diagram

The system context shows how the Certificate Manager interacts with external actors and systems.

```mermaid
C4Context
    title System Context — Federator Certificate Manager

    Person(ops, "Platform Engineer", "Configures and monitors the certificate manager")

    System(certMgr, "Federator Certificate Manager", "Automates X.509 certificate lifecycle for federator components")

    System_Ext(vault, "HashiCorp Vault", "KV v2 secrets engine for persisting keys, certificates, and passwords")
    System_Ext(mngNode, "Management Node", "PKI API — provides intermediate CA and signs CSRs")
    System_Ext(idp, "OAuth2 Identity Provider", "Issues JWT tokens via client credentials grant (e.g., Keycloak)")
    System_Ext(fs, "Filesystem", "Destination for PKCS#12 keystores consumed by federator services")

    Rel(ops, certMgr, "Deploys and configures", "application.yml / env vars")
    Rel(certMgr, vault, "Reads/writes secrets", "Vault HTTP API (KV v2)")
    Rel(certMgr, mngNode, "Requests intermediate CA, submits CSRs", "HTTPS + mTLS + Bearer token")
    Rel(certMgr, idp, "Acquires access tokens", "HTTPS + mTLS, client_credentials grant")
    Rel(certMgr, fs, "Writes keystore.p12, truststore.p12, password files", "Local I/O")

    UpdateRelStyle(ops, certMgr, $offsetY="-40")
    UpdateRelStyle(certMgr, vault, $offsetX="-80")
    UpdateRelStyle(certMgr, mngNode, $offsetX="40")
```

### Narrative

| System | Protocol | Authentication | Purpose |
|--------|----------|----------------|---------|
| **HashiCorp Vault** | HTTP/HTTPS (Vault API) | Vault token | Persist and retrieve key pairs, certificates, CA chains, and passwords |
| **Management Node** | HTTPS with mTLS | OAuth2 Bearer token | Fetch intermediate CA certificate; sign certificate signing requests |
| **OAuth2 IdP** | HTTPS with mTLS | Client credentials (client_id) | Obtain JWT access tokens for Management Node API calls |
| **Filesystem** | Local I/O | OS-level permissions | Write PKCS#12 keystores and password files for federator consumption |

---

## C4 Level 2: Container Diagram

The container diagram shows the runtime boundaries and the major deployable units.

```mermaid
C4Container
    title Container Diagram — Federator Certificate Manager

    Person(ops, "Platform Engineer", "Configures and monitors")

    Container_Boundary(app, "Federator Certificate Manager (JVM Process)") {
        Container(scheduler, "Task Scheduler", "Spring @Scheduled, 2 threads", "Triggers renewal and sync jobs at configurable intervals")
        Container(certSvc, "Certificate Manager Service", "Spring Service", "Orchestrates renewal: keygen → CSR → sign → persist")
        Container(syncSvc, "KeyStore Sync Service", "Spring Service", "Generates PKCS#12 stores and writes to filesystem")
        Container(pkiSvc, "PKI Service", "Bouncy Castle", "RSA key generation and PKCS#10 CSR creation")
        Container(mngClient, "Management Node Client", "Spring RestClient + mTLS", "REST calls for intermediate CA and CSR signing")
        Container(tokenSvc, "OAuth2 Token Service", "Spring RestClient + Caffeine", "Token acquisition and caching")
        Container(vaultProvider, "Vault Secret Provider", "Spring Cloud Vault", "KV v2 read/write operations")
        Container(fsSvc, "FileSystem Service", "Java NIO", "Atomic writes and content comparison")
    }

    System_Ext(vault, "HashiCorp Vault", "KV v2 secrets engine")
    System_Ext(mngNode, "Management Node", "PKI API")
    System_Ext(idp, "OAuth2 IdP", "Token endpoint")
    System_Ext(fs, "Filesystem", "PKCS#12 output")

    Rel(ops, scheduler, "Configures rates", "application.yml")
    Rel(scheduler, certSvc, "run()")
    Rel(scheduler, syncSvc, "syncKeyStoresToFilesystem()")
    Rel(certSvc, pkiSvc, "createKeyPair(), createCsr()")
    Rel(certSvc, mngClient, "signCertificate(), getIntermediateCertificate()")
    Rel(certSvc, vaultProvider, "persist*()")
    Rel(syncSvc, vaultProvider, "get*()")
    Rel(syncSvc, fsSvc, "atomicWrite()")
    Rel(mngClient, tokenSvc, "getToken()")
    Rel(tokenSvc, idp, "POST /token", "mTLS + client_credentials")
    Rel(mngClient, mngNode, "GET /intermediate, POST /csr/sign", "mTLS + Bearer")
    Rel(vaultProvider, vault, "KV v2 read/write", "Vault token")
    Rel(fsSvc, fs, "write keystore.p12, truststore.p12")
```

---

## C4 Level 3: Component Diagram

Detailed view of all Spring-managed components, their interfaces, and dependencies.

```mermaid
C4Component
    title Component Diagram — Certificate Manager Service Layer

    Container_Boundary(jobs, "Scheduled Jobs") {
        Component(renewalJob, "CertificateRenewalJob", "@Scheduled", "Fixed delay: renewal-rate, initial delay: 10s")
        Component(syncJob, "CertificateSyncJob", "@Scheduled", "Fixed delay: sync-rate, initial delay: 5s")
    }

    Container_Boundary(services, "Service Layer") {
        Component(certMgrSvc, "CertificateManagerServiceImpl", "Service", "Orchestrates renewal: intermediate CA check → keygen → CSR → sign → persist")
        Component(mngNodeSvc, "ManagementNodeServiceImpl", "Service", "REST client for Management Node API")
        Component(keyStoreSyncSvc, "KeyStoreSyncServiceImpl", "Service", "Generates and syncs PKCS#12 to filesystem")
    }

    Container_Boundary(pki, "PKI Layer") {
        Component(pkiSvc, "PkiService", "Service", "RSA key generation, PKCS#10 CSR creation")
        Component(keyStoreSvc, "KeyStoreService", "Service", "PKCS#12 keystore/truststore creation")
        Component(pemUtil, "PemUtil", "Utility", "PEM encode/decode, certificate validation, otherName SAN parsing")
    }

    Container_Boundary(infra, "Infrastructure Layer") {
        Component(vaultProv, "VaultSecretProviderImpl", "Service", "Vault KV v2 operations via VaultTemplate")
        Component(fsSvc, "FileSystemServiceImpl", "Service", "Atomic file writes, needs-update checks")
        Component(tokenCache, "TokenCacheServiceImpl", "Service", "Caffeine cache with 5-min early refresh")
        Component(oauth2Svc, "OAuth2TokenServiceImpl", "Service", "mTLS POST to IdP token endpoint")
    }

    Rel(renewalJob, certMgrSvc, "run()")
    Rel(syncJob, certMgrSvc, "sync()")
    Rel(certMgrSvc, pkiSvc, "createKeyPair(), createCsr()")
    Rel(certMgrSvc, mngNodeSvc, "signCertificate(), getIntermediateCertificate()")
    Rel(certMgrSvc, vaultProv, "persist*(), get*()")
    Rel(certMgrSvc, keyStoreSyncSvc, "syncKeyStoresToFilesystem()")
    Rel(keyStoreSyncSvc, vaultProv, "getKeyPair(), getCertificate(), getCaChain()")
    Rel(keyStoreSyncSvc, keyStoreSvc, "createKeyStore(), createTrustStore()")
    Rel(keyStoreSyncSvc, fsSvc, "atomicWrite(), needsUpdate()")
    Rel(mngNodeSvc, tokenCache, "getToken()")
    Rel(tokenCache, oauth2Svc, "getAccessToken()")
    Rel(pkiSvc, pemUtil, "toPem(), parsePkcs8PrivateKey()")
```

---

## Deployment Topology

```mermaid
graph TB
    subgraph "Deployment Environment"
        subgraph "Application Host"
            CM["Federator Certificate Manager<br/>(JVM Process)"]
            FS[("Filesystem<br/>/etc/federator/secrets/<br/>keystore.p12<br/>truststore.p12")]
        end

        subgraph "Infrastructure Services"
            V["HashiCorp Vault<br/>(KV v2 Engine)"]
            IDP["OAuth2 IdP<br/>(Keycloak)"]
        end

        subgraph "NDTP Services"
            MN["Management Node<br/>(PKI API)"]
            FED["Federator Service<br/>(consumes keystores)"]
        end
    end

    CM -- "Vault HTTP API<br/>Token auth" --> V
    CM -- "HTTPS + mTLS<br/>Client credentials" --> IDP
    CM -- "HTTPS + mTLS<br/>Bearer token" --> MN
    CM -- "Atomic write<br/>PKCS#12 + passwords" --> FS
    FED -- "Reads<br/>keystore.p12 / truststore.p12" --> FS
```

---

## Internal Dependency Graph

Shows the Spring bean injection dependencies between all service components.

```mermaid
graph TD
    subgraph "Scheduled Jobs"
        RJ[CertificateRenewalJob]
        SJ[CertificateSyncJob]
    end

    subgraph "Orchestration"
        CMS[CertificateManagerServiceImpl]
        KSS[KeyStoreSyncServiceImpl]
    end

    subgraph "External Communication"
        MNS[ManagementNodeServiceImpl]
        TCS[TokenCacheServiceImpl]
        OTS[OAuth2TokenServiceImpl]
    end

    subgraph "PKI & Cryptography"
        PKI[PkiService]
        KS[KeyStoreService]
        PU[PemUtil]
    end

    subgraph "Infrastructure"
        VSP[VaultSecretProviderImpl]
        FSS[FileSystemServiceImpl]
    end

    subgraph "Configuration"
        CP[CertificateProperties]
        RC[RestClientConfig → RestClient]
        CC[CacheConfig → CacheManager]
    end

    RJ --> CMS
    SJ --> CMS

    CMS --> MNS
    CMS --> PKI
    CMS --> VSP
    CMS --> CP
    CMS --> KSS
    CMS --> PU

    KSS --> VSP
    KSS --> KS
    KSS --> FSS
    KSS --> CP

    MNS --> TCS
    MNS --> RC

    TCS --> OTS
    TCS --> CC

    OTS --> RC

    PKI --> PU
```

---

## Threading Model

The application uses a `ThreadPoolTaskScheduler` with a pool size of 2, named `cert-mgr-*`:

| Thread | Job | Default Interval | Initial Delay |
|--------|-----|-----------------|---------------|
| `cert-mgr-1` | `CertificateRenewalJob` | 1 hour (`renewal-rate`) | 10 seconds |
| `cert-mgr-2` | `CertificateSyncJob` | 1 minute (`sync-rate`) | 5 seconds |

Both jobs invoke `CertificateManagerServiceImpl` methods synchronously. There is no concurrent access to shared mutable state — Vault operations and filesystem writes are serialised within each job's thread.

---

## Error Handling Strategy

Each integration boundary has a dedicated exception type:

```mermaid
graph LR
    subgraph "Exception Hierarchy"
        RE[RuntimeException]
        RE --> VE[VaultException]
        RE --> MNE[ManagementNodeException]
        RE --> PE[PkiException]
        RE --> OTE[OAuth2TokenException]
        RE --> FSE[FileSystemException]
        RE --> KSE[KeyStoreCreationException]
        RE --> RCE[RestClientConfigurationException]
    end
```

| Exception | Thrown By | Trigger |
|-----------|----------|---------|
| `VaultException` | `VaultSecretProviderImpl` | KV mount missing, read/write failures |
| `ManagementNodeException` | `ManagementNodeServiceImpl` | API call failures, unexpected responses |
| `PkiException` | `PkiService` | Key generation or CSR creation failures |
| `OAuth2TokenException` | `OAuth2TokenServiceImpl` | Token endpoint failures |
| `FileSystemException` | `FileSystemServiceImpl` | Filesystem I/O errors |
| `KeyStoreCreationException` | `KeyStoreService` | PKCS#12 creation or verification failures |
| `RestClientConfigurationException` | `RestClientConfig` | mTLS keystore loading failures |

All exceptions extend `RuntimeException` and propagate up to the scheduled job level, where they are logged. The scheduler continues to invoke the job at the next interval — no circuit-breaking or retry logic is applied at the job level.

© Crown Copyright 2026. This work has been developed by the National Digital Twin Programme and is legally attributed to the UK's Department for Business, Innovation, Science and Trade (BIST) as the governing entity.
  
Licensed under the Open Government Licence v3.0.  