/*
 * SPDX-License-Identifier: Apache-2.0
 * © Crown Copyright 2026. This work has been developed by the National Digital Twin Programme and is legally
 * attributed to the UK's Department for Business, Innovation, Science and Trade (BIST) as the governing entity.
 */

package uk.gov.dbt.ndtp.federator.certificate.manager.service;

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
import uk.gov.dbt.ndtp.federator.certificate.manager.exception.FileSystemException;
import uk.gov.dbt.ndtp.federator.certificate.manager.exception.KeyStoreCreationException;
import uk.gov.dbt.ndtp.federator.certificate.manager.model.dto.CreateKeyResponseDTO;
import uk.gov.dbt.ndtp.federator.certificate.manager.service.pki.KeyStoreService;
import uk.gov.dbt.ndtp.federator.certificate.manager.service.pki.VaultSecretProvider;
import uk.gov.dbt.ndtp.federator.certificate.manager.service.pki.cryptography.PemUtil;

/**
 * Implementation of KeyStoreSyncService.
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

    @Override
    public void syncKeyStoresToFilesystem() {
        log.info("Synchronizing keystores to filesystem...");
        CertificateProperties.Destination config = certificateProperties.getDestination();
        Path basePath = Paths.get(config.getPath());

        String keystorePassword = resolvePassword(config.getKeystorePassword(), "keystore-password");
        String truststorePassword = resolvePassword(config.getTruststorePassword(), "truststore-password");

        String certificatePem = vaultSecretProvider.getCertificate();
        CreateKeyResponseDTO keyPair = vaultSecretProvider.getKeyPair();
        List<String> caChain = resolveCaChain();

        syncKeyStore(config, basePath, keystorePassword, certificatePem, keyPair, caChain);
        syncTrustStore(config, basePath, truststorePassword, caChain);
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

    private void syncKeyStore(
            CertificateProperties.Destination config,
            Path basePath,
            String keystorePassword,
            String certificatePem,
            CreateKeyResponseDTO keyPair,
            List<String> caChain) {
        if (certificatePem == null || keyPair == null || keyPair.getPrivateKeyPem() == null) {
            log.warn("Missing certificate or key pair in Vault. Skipping keystore synchronization.");
            return;
        }
        Path keystorePath = basePath.resolve(config.getKeystoreFile());
        boolean needsUpdate = shouldUpdateKeyStore(
                keystorePath,
                keystorePassword,
                keyPair.getPrivateKeyPem(),
                certificatePem,
                caChain,
                config.getKeystoreAlias());

        if (needsUpdate) {
            byte[] keystoreBytes = keyStoreService.createKeyStore(
                    keyPair.getPrivateKeyPem(), certificatePem, caChain, keystorePassword, config.getKeystoreAlias());
            validateKeyStore(keystoreBytes, keystorePassword, config.getKeystoreAlias());
            fileSystemService.atomicWrite(keystorePath, keystoreBytes);
            log.info("Keystore synchronized to {}", keystorePath);
        } else {
            log.debug("Keystore at {} is already in sync with Vault. Skipping update.", keystorePath);
        }
        writePasswordToFile(keystorePath, config.getKeystorePasswordFile(), keystorePassword);
    }

    private void syncTrustStore(
            CertificateProperties.Destination config, Path basePath, String truststorePassword, List<String> caChain) {
        if (caChain == null || caChain.isEmpty()) {
            log.warn("Missing CA chain in Vault. Skipping truststore synchronization.");
            return;
        }
        Path truststorePath = basePath.resolve(config.getTruststoreFile());
        boolean needsUpdate = shouldUpdateTrustStore(truststorePath, truststorePassword, caChain);

        if (needsUpdate) {
            byte[] truststoreBytes = keyStoreService.createTrustStore(caChain, truststorePassword, truststorePath);
            validateTrustStore(truststoreBytes, truststorePassword);
            fileSystemService.atomicWrite(truststorePath, truststoreBytes);
            log.info("Truststore synchronized to {}", truststorePath);
        } else {
            log.debug("Truststore at {} is already in sync with Vault. Skipping update.", truststorePath);
        }
        writePasswordToFile(truststorePath, config.getTruststorePasswordFile(), truststorePassword);
    }

    private boolean shouldUpdateKeyStore(
            Path path,
            String password,
            String privateKeyPem,
            String certificatePem,
            List<String> caChain,
            String alias) {
        if (!Files.exists(path)) {
            return true;
        }
        try {
            KeyStore ks = loadKeyStore(path, password);

            // 1. Check if alias exists
            if (!ks.containsAlias(alias)) return true;

            // 2. Check if private key matches
            Key key = ks.getKey(alias, password.toCharArray());
            if (key == null) return true;
            PrivateKey existingPriv = (PrivateKey) key;
            PrivateKey newPriv = PemUtil.parsePkcs8PrivateKey(privateKeyPem);
            if (!Arrays.equals(existingPriv.getEncoded(), newPriv.getEncoded())) return true;

            // 3. Check certificate chain
            Certificate[] existingChain = ks.getCertificateChain(alias);
            if (existingChain == null) return true;

            List<X509Certificate> newChain = new ArrayList<>();
            newChain.add(PemUtil.parseCertificate(certificatePem));
            if (caChain != null) {
                for (String ca : caChain) {
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
            log.warn("Failed to validate existing keystore {}: {}. Assuming update is needed.", path, e.getMessage());
            return true;
        }
    }

    private boolean shouldUpdateTrustStore(Path path, String password, List<String> caChain) {
        if (!Files.exists(path)) {
            return true;
        }
        try {
            KeyStore ks = loadKeyStore(path, password);

            if (caChain == null) return ks.size() > 0;

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
            log.warn("Failed to validate existing truststore {}: {}. Assuming update is needed.", path, e.getMessage());
            return true;
        }
    }

    private KeyStore loadKeyStore(Path path, String password)
            throws KeyStoreException, IOException, NoSuchAlgorithmException, CertificateException {
        KeyStore ks = KeyStore.getInstance(PKCS_12);
        try (InputStream is = Files.newInputStream(path)) {
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
