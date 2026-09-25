/*
 * SPDX-License-Identifier: Apache-2.0
 * © Crown Copyright 2026. This work has been developed by the National Digital Twin Programme and is legally
 * attributed to the UK's Department for Business, Innovation, Science and Trade (BIST) as the governing entity.
 */

package uk.gov.dbt.ndtp.federator.certificate.manager.service.pki;

import io.github.resilience4j.circuitbreaker.annotation.CircuitBreaker;
import io.github.resilience4j.retry.annotation.Retry;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.vault.core.VaultSysOperations;
import org.springframework.vault.core.VaultTemplate;
import org.springframework.vault.core.VaultVersionedKeyValueOperations;
import org.springframework.vault.support.VaultMount;
import org.springframework.vault.support.Versioned;
import uk.gov.dbt.ndtp.federator.certificate.manager.exception.VaultException;
import uk.gov.dbt.ndtp.federator.certificate.manager.model.dto.CreateKeyResponseDTO;

/**
 * Implementation of {@link VaultSecretProvider} for persisting key pairs to HashiCorp Vault.
 * Ensures the KV secrets engine mount exists and uses KV v2 for storing secrets.
 */
@Slf4j
@Service
public class VaultSecretProviderImpl implements VaultSecretProvider {

    public static final String CERTIFICATE = "certificate";
    public static final String STRING_DELIMITER = "/";
    public static final String PUBLIC_KEY = "publicKey";
    public static final String PRIVATE_KEY = "privateKey";
    public static final String KEYPAIR = "keypair";
    private final VaultTemplate vaultTemplate;
    private final String mountPath; // e.g. "node-net"
    private final String baseRelativePath; // e.g. "client"
    private volatile boolean mountVerified;

    /**
     * Constructs the VaultSecretProviderImpl.
     *
     * @param vaultTemplate the Spring Vault template
     * @param secretBasePath the base path for secrets from configuration (e.g., "node-net/client")
     */
    public VaultSecretProviderImpl(
            VaultTemplate vaultTemplate, @Value("${application.vault.secret-path}") String secretBasePath) {
        this.vaultTemplate = vaultTemplate;
        String[] parts = secretBasePath.split(STRING_DELIMITER, 2);
        this.mountPath = parts[0];
        this.baseRelativePath = parts.length > 1 ? parts[1] : "";
    }

    /**
     * Persists the provided key pair to the configured Vault secret path.
     * Ensures that the KV engine is mounted at the given mount path (KV v2). If not, it mounts it.
     *
     * @param keyPairDto the DTO containing the public and private keys in PEM format
     */
    @Retry(name = "vault")
    @CircuitBreaker(name = "vault")
    @Override
    public void persistKeyPair(CreateKeyResponseDTO keyPairDto) {
        ensureKvMountExists();

        String relativePath = getRelativePath(KEYPAIR);
        log.debug("Persisting key pair to Vault path: {}/{} (KV v2)", mountPath, relativePath);

        Map<String, String> keyPairMap = new HashMap<>();
        keyPairMap.put(PUBLIC_KEY, keyPairDto.getPublicKeyPem());
        keyPairMap.put(PRIVATE_KEY, keyPairDto.getPrivateKeyPem());

        persist(relativePath, keyPairMap, "key pair");
    }

    /**
     * Persists the provided certificate to the configured Vault secret path.
     *
     * @param certificate the certificate in PEM format
     */
    @Retry(name = "vault")
    @CircuitBreaker(name = "vault")
    @Override
    public void persistCertificate(String certificate) {
        ensureKvMountExists();

        String relativePath = getRelativePath(CERTIFICATE);
        log.debug("Persisting certificate to Vault path: {}/{} (KV v2)", mountPath, relativePath);

        Map<String, String> data = new HashMap<>();
        data.put(CERTIFICATE, certificate);

        persist(relativePath, data, CERTIFICATE);
    }

    /**
     * Persists the provided CA chain to the configured Vault secret path.
     *
     * @param caChain the list of certificates in the chain in PEM format
     */
    @Retry(name = "vault")
    @CircuitBreaker(name = "vault")
    @Override
    public void persistCaChain(List<String> caChain) {
        ensureKvMountExists();

        String relativePath = getRelativePath("ca-chain");
        log.debug("Persisting CA chain to Vault path: {}/{} (KV v2)", mountPath, relativePath);

        String chain = String.join("\n", caChain);
        Map<String, String> data = new HashMap<>();
        data.put("chain", chain);

        persist(relativePath, data, "CA chain");
    }

    /**
     * Persists the provided Intermediate CA certificate to the configured Vault secret path.
     *
     * @param intermediateCa the Intermediate CA certificate in PEM format
     */
    @Retry(name = "vault")
    @CircuitBreaker(name = "vault")
    @Override
    public void persistIntermediateCa(String intermediateCa) {
        ensureKvMountExists();

        String relativePath = getRelativePath("intermediate-ca");
        log.debug("Persisting Intermediate CA to Vault path: {}/{} (KV v2)", mountPath, relativePath);

        Map<String, String> data = new HashMap<>();
        data.put(CERTIFICATE, intermediateCa);

        persist(relativePath, data, "Intermediate CA");
    }

    private String getRelativePath(String suffix) {
        return baseRelativePath.isEmpty() ? suffix : baseRelativePath + STRING_DELIMITER + suffix;
    }

    @Retry(name = "vault")
    @CircuitBreaker(name = "vault")
    @Override
    public String getCertificate() {
        ensureKvMountExists();
        String relativePath = getRelativePath(CERTIFICATE);
        log.debug("Retrieving certificate from Vault path: {}/{} (KV v2)", mountPath, relativePath);
        try {
            VaultVersionedKeyValueOperations kv = vaultTemplate.opsForVersionedKeyValue(mountPath);
            Versioned<Map<String, Object>> versioned = kv.get(relativePath);
            if (versioned == null || versioned.getData() == null) {
                log.warn("No certificate found at {}/{}", mountPath, relativePath);
                return null;
            }
            Object cert = versioned.getData().get(CERTIFICATE);
            if (cert instanceof String s) {
                return s;
            }
            return null;
        } catch (Exception e) {
            log.error("Failed to retrieve certificate from Vault at path {}/{}", mountPath, relativePath, e);
            throw new VaultException("Vault retrieval failed", e);
        }
    }

    @Retry(name = "vault")
    @CircuitBreaker(name = "vault")
    @Override
    public CreateKeyResponseDTO getKeyPair() {
        ensureKvMountExists();
        String relativePath = getRelativePath(KEYPAIR);
        log.debug("Retrieving key pair from Vault path: {}/{} (KV v2)", mountPath, relativePath);
        try {
            VaultVersionedKeyValueOperations kv = vaultTemplate.opsForVersionedKeyValue(mountPath);
            Versioned<Map<String, Object>> versioned = kv.get(relativePath);
            if (versioned == null || versioned.getData() == null) {
                log.warn("No key pair found at {}/{}", mountPath, relativePath);
                return null;
            }
            Map<String, Object> data = versioned.getData();
            Object publicKeyObj = data.get(PUBLIC_KEY);
            Object privateKeyObj = data.get(PRIVATE_KEY);
            String publicKey = publicKeyObj instanceof String s ? s : null;
            String privateKey = privateKeyObj instanceof String s ? s : null;
            return CreateKeyResponseDTO.builder()
                    .publicKeyPem(publicKey)
                    .privateKeyPem(privateKey)
                    .build();
        } catch (Exception e) {
            log.error("Failed to retrieve key pair from Vault at path {}/{}", mountPath, relativePath, e);
            throw new VaultException("Vault retrieval failed", e);
        }
    }

    @Retry(name = "vault")
    @CircuitBreaker(name = "vault")
    @Override
    public List<String> getCaChain() {
        ensureKvMountExists();
        String relativePath = getRelativePath("ca-chain");
        log.debug("Retrieving CA chain from Vault path: {}/{} (KV v2)", mountPath, relativePath);
        try {
            VaultVersionedKeyValueOperations kv = vaultTemplate.opsForVersionedKeyValue(mountPath);
            Versioned<Map<String, Object>> versioned = kv.get(relativePath);
            if (versioned == null || versioned.getData() == null) {
                log.warn("No CA chain found at {}/{}", mountPath, relativePath);
                return Collections.emptyList();
            }
            String chainStr = (String) versioned.getData().get("chain");
            return splitPemChain(chainStr);
        } catch (Exception e) {
            log.error("Failed to retrieve CA chain from Vault at path {}/{}", mountPath, relativePath, e);
            throw new VaultException("Vault retrieval failed", e);
        }
    }

    private List<String> splitPemChain(String pemChain) {
        if (pemChain == null || pemChain.isBlank()) {
            return Collections.emptyList();
        }
        String[] parts = pemChain.split("-----END CERTIFICATE-----");
        List<String> certs = new ArrayList<>();
        for (String part : parts) {
            String block = part.trim();
            if (!block.isBlank()) {
                if (!block.contains("-----BEGIN CERTIFICATE-----")) {
                    continue;
                }
                certs.add(block + "\n-----END CERTIFICATE-----\n");
            }
        }
        return certs;
    }

    @Retry(name = "vault")
    @CircuitBreaker(name = "vault")
    @Override
    public String getIntermediateCa() {
        ensureKvMountExists();
        String relativePath = getRelativePath("intermediate-ca");
        log.debug("Retrieving Intermediate CA from Vault path: {}/{} (KV v2)", mountPath, relativePath);
        try {
            VaultVersionedKeyValueOperations kv = vaultTemplate.opsForVersionedKeyValue(mountPath);
            Versioned<Map<String, Object>> versioned = kv.get(relativePath);
            if (versioned == null || versioned.getData() == null) {
                log.warn("No Intermediate CA found at {}/{}", mountPath, relativePath);
                return null;
            }
            Object cert = versioned.getData().get(CERTIFICATE);
            if (cert instanceof String s) {
                return s;
            }
            return null;
        } catch (Exception e) {
            log.error("Failed to retrieve Intermediate CA from Vault at path {}/{}", mountPath, relativePath, e);
            throw new VaultException("Vault retrieval failed", e);
        }
    }

    @Retry(name = "vault")
    @CircuitBreaker(name = "vault")
    @Override
    public void persistSecret(String suffix, Map<String, String> secret) {
        ensureKvMountExists();
        String relativePath = getRelativePath(suffix);
        log.debug("Persisting secret to Vault path: {}/{} (KV v2)", mountPath, relativePath);
        persist(relativePath, secret, "generic secret [" + suffix + "]");
    }

    @Retry(name = "vault")
    @CircuitBreaker(name = "vault")
    @Override
    public Map<String, Object> getSecret(String suffix) {
        ensureKvMountExists();
        String relativePath = getRelativePath(suffix);
        log.debug("Retrieving secret from Vault path: {}/{} (KV v2)", mountPath, relativePath);
        try {
            VaultVersionedKeyValueOperations kv = vaultTemplate.opsForVersionedKeyValue(mountPath);
            Versioned<Map<String, Object>> versioned = kv.get(relativePath);
            if (versioned == null || versioned.getData() == null) {
                log.warn("No secret found at {}/{}", mountPath, relativePath);
                return Collections.emptyMap();
            }
            return versioned.getData();
        } catch (Exception e) {
            log.error("Failed to retrieve secret from Vault at path {}/{}", mountPath, relativePath, e);
            throw new VaultException("Vault retrieval failed", e);
        }
    }

    private void persist(String relativePath, Map<String, String> data, String type) {
        try {
            VaultVersionedKeyValueOperations kv = vaultTemplate.opsForVersionedKeyValue(mountPath);
            kv.put(relativePath, data);
            log.info("Successfully persisted {} to Vault.", type);
        } catch (Exception e) {
            log.error("Failed to persist {} to Vault at path {}/{}", type, mountPath, relativePath, e);
            throw new VaultException("Vault persistence failed", e);
        }
    }

    /**
     * Ensures the KV (v2) engine is mounted at the configured mountPath.
     * If the mount does not exist, it will throw a VaultException.
     * Result is cached after first successful check.
     */
    void ensureKvMountExists() {
        if (mountVerified) {
            return;
        }
        try {
            VaultSysOperations sys = vaultTemplate.opsForSys();
            Map<String, VaultMount> mounts = sys.getMounts();
            String key = mountPath.endsWith(STRING_DELIMITER) ? mountPath : mountPath + STRING_DELIMITER;
            if (!mounts.containsKey(key)) {
                log.error("Vault mount '{}' not found. Please provision KV v2 at this path.", key);
                throw new VaultException("Vault mount '" + key + "' not found. Required for secret persistence.");
            }
            mountVerified = true;
        } catch (VaultException e) {
            throw e;
        } catch (Exception e) {
            log.error("Failed to ensure KV mount exists at '{}'", mountPath, e);
            throw new VaultException("Failed to verify KV mount existence", e);
        }
    }
}
