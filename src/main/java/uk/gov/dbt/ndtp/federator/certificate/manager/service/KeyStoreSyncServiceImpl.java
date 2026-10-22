/*
 * SPDX-License-Identifier: Apache-2.0
 * © Crown Copyright 2026. This work has been developed by the National Digital Twin Programme and is legally
 * attributed to the UK's Department for Business, Innovation, Science and Trade (BIST) as the governing entity.
 */

package uk.gov.dbt.ndtp.federator.certificate.manager.service;

import static uk.gov.dbt.ndtp.federator.certificate.manager.config.CertificateProperties.Destination.KEYSTORE_PASSWORD_NAME;
import static uk.gov.dbt.ndtp.federator.certificate.manager.config.CertificateProperties.Destination.TRUSTSTORE_PASSWORD_NAME;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.time.Clock;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import uk.gov.dbt.ndtp.federator.certificate.manager.config.CertificateProperties;
import uk.gov.dbt.ndtp.federator.certificate.manager.config.CertificateProperties.StoreLocation;
import uk.gov.dbt.ndtp.federator.certificate.manager.exception.FileSystemException;
import uk.gov.dbt.ndtp.federator.certificate.manager.exception.KeyStoreCreationException;
import uk.gov.dbt.ndtp.federator.certificate.manager.model.dto.CreateKeyResponseDTO;
import uk.gov.dbt.ndtp.federator.certificate.manager.service.pki.KeyStoreService;
import uk.gov.dbt.ndtp.federator.certificate.manager.service.pki.VaultSecretProvider;
import uk.gov.dbt.ndtp.federator.certificate.manager.service.pki.cryptography.PemUtil;

/**
 * Implementation of KeyStoreSyncService.
 * Builds the keystore and truststore from the material in Vault and writes them, together with their passwords,
 * to each configured destination: the filesystem ({@code destination.file}), a Vault KV v2 secret
 * ({@code destination.vault}), or both.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class KeyStoreSyncServiceImpl implements KeyStoreSyncService {

    private static final String PASSWORD = "password";
    private static final String PKCS_12 = "PKCS12";
    private static final SecureRandom RANDOM = new SecureRandom();
    private final CertificateProperties certificateProperties;
    private final VaultSecretProvider vaultSecretProvider;
    private final KeyStoreService keyStoreService;
    private final FileSystemService fileSystemService;

    /**
     * Vault destination attributes recording when the secret was first written and when its content last changed.
     */
    static final String CREATED_AT = "createdAt";

    static final String UPDATED_AT = "updatedAt";

    private Clock clock = Clock.systemUTC();

    void setClock(Clock clock) {
        this.clock = clock;
    }

    /**
     * The material every destination is built from.
     */
    private record StoreMaterial(
            String certificatePem,
            CreateKeyResponseDTO keyPair,
            List<String> caChain,
            String keystorePassword,
            String truststorePassword) {

        boolean hasKeyStoreMaterial() {
            return certificatePem != null && keyPair != null && keyPair.getPrivateKeyPem() != null;
        }

        boolean hasCaChain() {
            return caChain != null && !caChain.isEmpty();
        }
    }

    @Override
    public void syncKeyStores() {
        CertificateProperties.Destination config = certificateProperties.getDestination();
        StoreLocation file = config.getFile();
        StoreLocation vault = config.getVault();
        boolean toFile = file != null && file.isEnabled();
        boolean toVault = vault != null && vault.isEnabled();
        if (!toFile && !toVault) {
            log.warn("No keystore destination configured (destination.file / destination.vault). Skipping sync.");
            return;
        }
        log.info(
                "Synchronizing keystores to {}",
                toFile && toVault ? "filesystem and Vault" : toFile ? "filesystem" : "Vault");

        String keystorePassword = resolvePassword(config.getKeystorePassword(), "keystore-password");
        String truststorePassword = resolvePassword(config.getTruststorePassword(), "truststore-password");
        String certificatePem = vaultSecretProvider.getCertificate();
        CreateKeyResponseDTO keyPair = vaultSecretProvider.getKeyPair();
        if (certificatePem != null
                && keyPair != null
                && keyPair.getPrivateKeyPem() != null
                && !PemUtil.privateKeyMatchesCertificate(keyPair.getPrivateKeyPem(), certificatePem)) {
            // e.g. a renewal elsewhere has written one but not yet the other; never publish a mismatched keystore
            log.warn("Key pair in Vault does not match the certificate. Skipping keystore until they match.");
            certificatePem = null;
            keyPair = null;
        }
        StoreMaterial material =
                new StoreMaterial(certificatePem, keyPair, resolveCaChain(), keystorePassword, truststorePassword);

        if (toFile) {
            Path basePath = Paths.get(file.getPath());
            syncKeyStore(file, basePath, material);
            syncTrustStore(file, basePath, material);
        }
        if (toVault) {
            syncToVault(vault, material);
        }
    }

    private List<String> resolveCaChain() {
        List<String> caChain = vaultSecretProvider.getCaChain();
        if (caChain != null && !caChain.isEmpty()) {
            return caChain;
        }
        String intermediateCa = vaultSecretProvider.getIntermediateCa();
        if (intermediateCa != null && !intermediateCa.isBlank()) {
            log.info("CA chain is empty, falling back to signing CA for truststore");
            return List.of(intermediateCa);
        }
        return caChain;
    }

    // --- filesystem destination ---

    private void syncKeyStore(StoreLocation config, Path basePath, StoreMaterial material) {
        if (!material.hasKeyStoreMaterial()) {
            log.warn("No matching certificate and key pair in Vault. Skipping keystore synchronization.");
            return;
        }
        Path keystorePath = basePath.resolve(config.getKeystoreFile());
        boolean needsUpdate = !Files.exists(keystorePath)
                || keyStoreDiffers(
                        readFile(keystorePath), keystorePath.toString(), material, config.getKeystoreAlias());

        if (needsUpdate) {
            fileSystemService.atomicWrite(keystorePath, buildKeyStore(material, config.getKeystoreAlias()));
            log.info("Keystore synchronized to {}", keystorePath);
        } else {
            log.debug("Keystore at {} is already in sync with Vault. Skipping update.", keystorePath);
        }
        writePasswordToFile(keystorePath, KEYSTORE_PASSWORD_NAME, material.keystorePassword());
    }

    private void syncTrustStore(StoreLocation config, Path basePath, StoreMaterial material) {
        if (!material.hasCaChain()) {
            log.warn("Missing CA chain in Vault. Skipping truststore synchronization.");
            return;
        }
        Path truststorePath = basePath.resolve(config.getTruststoreFile());
        boolean needsUpdate = !Files.exists(truststorePath)
                || trustStoreDiffers(readFile(truststorePath), truststorePath.toString(), material);

        if (needsUpdate) {
            fileSystemService.atomicWrite(truststorePath, buildTrustStore(material, truststorePath));
            log.info("Truststore synchronized to {}", truststorePath);
        } else {
            log.debug("Truststore at {} is already in sync with Vault. Skipping update.", truststorePath);
        }
        writePasswordToFile(truststorePath, TRUSTSTORE_PASSWORD_NAME, material.truststorePassword());
    }

    private static byte[] readFile(Path path) {
        try {
            return Files.readAllBytes(path);
        } catch (IOException e) {
            log.warn("Failed to read existing store {}: {}. Assuming update is needed.", path, e.getMessage());
            return new byte[0];
        }
    }

    // --- Vault destination ---

    /**
     * Writes the stores (Base64-encoded) and their passwords to a single KV v2 secret. A new secret version is
     * only written when something changed, e.g. after a certificate rotation or a password change. Each write
     * sets {@code updatedAt}; {@code createdAt} is set on the first write and kept afterwards (ISO-8601, UTC).
     */
    private void syncToVault(StoreLocation config, StoreMaterial material) {
        if (!material.hasKeyStoreMaterial() && !material.hasCaChain()) {
            log.warn("Missing certificate material in Vault. Skipping Vault destination synchronization.");
            return;
        }
        String path = config.getPath();
        Map<String, Object> existing = vaultSecretProvider.getSecretAtPath(path);
        Map<String, String> data = new HashMap<>();
        existing.forEach((key, value) -> {
            if (value instanceof String str) data.put(key, str);
        });
        boolean changed = false;

        if (material.hasKeyStoreMaterial()) {
            byte[] current = decodeBase64(existing.get(config.getKeystoreFile()));
            if (current == null
                    || keyStoreDiffers(
                            current,
                            vaultLocation(path, config.getKeystoreFile()),
                            material,
                            config.getKeystoreAlias())) {
                data.put(config.getKeystoreFile(), encodeBase64(buildKeyStore(material, config.getKeystoreAlias())));
                changed = true;
            }
            changed |= putIfChanged(data, KEYSTORE_PASSWORD_NAME, material.keystorePassword());
        } else {
            log.warn("No matching certificate and key pair in Vault. Skipping keystore for Vault destination.");
        }

        if (material.hasCaChain()) {
            byte[] current = decodeBase64(existing.get(config.getTruststoreFile()));
            if (current == null
                    || trustStoreDiffers(current, vaultLocation(path, config.getTruststoreFile()), material)) {
                data.put(config.getTruststoreFile(), encodeBase64(buildTrustStore(material, null)));
                changed = true;
            }
            changed |= putIfChanged(data, TRUSTSTORE_PASSWORD_NAME, material.truststorePassword());
        } else {
            log.warn("Missing CA chain in Vault. Skipping truststore for Vault destination.");
        }

        // Secrets written before the timestamps existed get them on the next sync
        changed |= !data.containsKey(CREATED_AT) || !data.containsKey(UPDATED_AT);

        if (changed) {
            String now = Instant.now(clock).truncatedTo(ChronoUnit.SECONDS).toString();
            data.putIfAbsent(CREATED_AT, now);
            data.put(UPDATED_AT, now);
            vaultSecretProvider.persistSecretAtPath(path, data);
            log.info("Keystore and truststore synchronized to Vault path {}", path);
        } else {
            log.debug("Vault path {} is already in sync. Skipping update.", path);
        }
    }

    private static boolean putIfChanged(Map<String, String> data, String key, String value) {
        return !value.equals(data.put(key, value));
    }

    private static String vaultLocation(String path, String attribute) {
        return "vault:" + path + "#" + attribute;
    }

    private static String encodeBase64(byte[] bytes) {
        return Base64.getEncoder().encodeToString(bytes);
    }

    private static byte[] decodeBase64(Object value) {
        if (!(value instanceof String str) || str.isBlank()) {
            return null;
        }
        try {
            return Base64.getDecoder().decode(str);
        } catch (IllegalArgumentException e) {
            log.warn("Existing Vault store value is not valid Base64. Assuming update is needed.");
            return null;
        }
    }

    // --- building and comparing stores ---

    private byte[] buildKeyStore(StoreMaterial material, String alias) {
        byte[] keystoreBytes = keyStoreService.createKeyStore(
                material.keyPair().getPrivateKeyPem(),
                material.certificatePem(),
                material.caChain(),
                material.keystorePassword(),
                alias);
        validateKeyStore(keystoreBytes, material.keystorePassword(), alias);
        return keystoreBytes;
    }

    private byte[] buildTrustStore(StoreMaterial material, Path existingTrustStore) {
        byte[] truststoreBytes =
                keyStoreService.createTrustStore(material.caChain(), material.truststorePassword(), existingTrustStore);
        validateTrustStore(truststoreBytes, material.truststorePassword());
        return truststoreBytes;
    }

    private boolean keyStoreDiffers(byte[] existing, String location, StoreMaterial material, String alias) {
        String password = material.keystorePassword();
        try {
            KeyStore ks = loadKeyStore(existing, password);

            // 1. Check if alias exists
            if (!ks.containsAlias(alias)) return true;

            // 2. Check if private key matches
            Key key = ks.getKey(alias, password.toCharArray());
            if (key == null) return true;
            PrivateKey existingPriv = (PrivateKey) key;
            PrivateKey newPriv = PemUtil.parsePkcs8PrivateKey(material.keyPair().getPrivateKeyPem());
            if (!Arrays.equals(existingPriv.getEncoded(), newPriv.getEncoded())) return true;

            // 3. Check certificate chain
            Certificate[] existingChain = ks.getCertificateChain(alias);
            if (existingChain == null) return true;

            List<X509Certificate> newChain = new ArrayList<>();
            newChain.add(PemUtil.parseCertificate(material.certificatePem()));
            if (material.caChain() != null) {
                for (String ca : material.caChain()) {
                    newChain.add(PemUtil.parseCertificate(ca));
                }
            }

            if (existingChain.length != newChain.size()) return true;
            for (int i = 0; i < existingChain.length; i++) {
                if (!Arrays.equals(
                        existingChain[i].getEncoded(), newChain.get(i).getEncoded())) return true;
            }

            return false;
        } catch (KeyStoreException
                | UnrecoverableKeyException
                | NoSuchAlgorithmException
                | CertificateException
                | IOException e) {
            log.warn(
                    "Failed to validate existing keystore {}: {}. Assuming update is needed.",
                    location,
                    e.getMessage());
            return true;
        }
    }

    private boolean trustStoreDiffers(byte[] existing, String location, StoreMaterial material) {
        List<String> caChain = material.caChain();
        try {
            KeyStore ks = loadKeyStore(existing, material.truststorePassword());

            if (ks.size() != caChain.size()) return true;

            for (int i = 0; i < caChain.size(); i++) {
                String alias = "ca-" + i;
                if (!ks.containsAlias(alias)) return true;
                Certificate existingCert = ks.getCertificate(alias);
                X509Certificate newCert = PemUtil.parseCertificate(caChain.get(i));
                if (!Arrays.equals(existingCert.getEncoded(), newCert.getEncoded())) return true;
            }

            return false;
        } catch (KeyStoreException | NoSuchAlgorithmException | CertificateException | IOException e) {
            log.warn(
                    "Failed to validate existing truststore {}: {}. Assuming update is needed.",
                    location,
                    e.getMessage());
            return true;
        }
    }

    private KeyStore loadKeyStore(byte[] bytes, String password)
            throws KeyStoreException, IOException, NoSuchAlgorithmException, CertificateException {
        KeyStore ks = KeyStore.getInstance(PKCS_12);
        try (InputStream is = new ByteArrayInputStream(bytes)) {
            ks.load(is, password.toCharArray());
        }
        return ks;
    }

    String resolvePassword(String configuredPassword, String vaultSuffix) {
        if (configuredPassword != null && !configuredPassword.isBlank()) {
            return configuredPassword;
        }

        Map<String, Object> secret = vaultSecretProvider.getSecret(vaultSuffix);
        if (secret.containsKey(PASSWORD)) {
            return (String) secret.get(PASSWORD);
        }

        log.info("Generating new password for {}", vaultSuffix);
        String generated = generateSecurePassword();
        Map<String, String> data = new HashMap<>();
        data.put(PASSWORD, generated);
        vaultSecretProvider.persistSecret(vaultSuffix, data);
        return generated;
    }

    private String generateSecurePassword() {
        byte[] bytes = new byte[24];
        RANDOM.nextBytes(bytes);
        return Base64.getEncoder().encodeToString(bytes);
    }

    private void writePasswordToFile(Path storePath, String passwordFileName, String password) {
        Path parentDir = storePath.getParent();
        if (parentDir == null) {
            parentDir = Paths.get(".");
        }
        Path passwordFile = parentDir.resolve(passwordFileName);

        byte[] newPasswordBytes = password.getBytes(StandardCharsets.UTF_8);
        try {
            if (fileSystemService.needsUpdate(passwordFile, newPasswordBytes)) {
                fileSystemService.write(passwordFile, newPasswordBytes);
                log.info("Password written to {}", passwordFile);
            } else {
                log.debug("Password file at {} is already in sync. Skipping update.", passwordFile);
            }
        } catch (FileSystemException e) {
            log.error("Failed to write password file to {}", passwordFile, e);
            throw e;
        }
    }

    private void validateKeyStore(byte[] bytes, String password, String alias) {
        try {
            KeyStore ks = KeyStore.getInstance(PKCS_12);
            ks.load(new ByteArrayInputStream(bytes), password.toCharArray());
            if (!ks.containsAlias(alias)) {
                throw new KeyStoreCreationException("Generated keystore missing expected alias: " + alias);
            }
        } catch (KeyStoreCreationException e) {
            throw e;
        } catch (KeyStoreException | IOException | NoSuchAlgorithmException | CertificateException e) {
            throw new KeyStoreCreationException("Failed to validate generated keystore", e);
        }
    }

    private void validateTrustStore(byte[] bytes, String password) {
        try {
            KeyStore ks = KeyStore.getInstance(PKCS_12);
            ks.load(new ByteArrayInputStream(bytes), password.toCharArray());
        } catch (KeyStoreException | IOException | NoSuchAlgorithmException | CertificateException e) {
            throw new KeyStoreCreationException("Failed to validate generated truststore", e);
        }
    }
}
