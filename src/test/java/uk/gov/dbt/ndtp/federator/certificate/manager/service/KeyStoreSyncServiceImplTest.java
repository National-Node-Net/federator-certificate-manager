/*
 * SPDX-License-Identifier: Apache-2.0
 * © Crown Copyright 2026. This work has been developed by the National Digital Twin Programme and is legally
 * attributed to the UK's Department for Business, Innovation, Science and Trade (BIST) as the governing entity.
 */

package uk.gov.dbt.ndtp.federator.certificate.manager.service;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

import java.io.ByteArrayInputStream;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Base64;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.apache.hc.client5.http.impl.io.PoolingHttpClientConnectionManager;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import uk.gov.dbt.ndtp.federator.certificate.manager.config.CertificateProperties;
import uk.gov.dbt.ndtp.federator.certificate.manager.exception.FileSystemException;
import uk.gov.dbt.ndtp.federator.certificate.manager.exception.KeyStoreCreationException;
import uk.gov.dbt.ndtp.federator.certificate.manager.model.dto.CreateKeyResponseDTO;
import uk.gov.dbt.ndtp.federator.certificate.manager.service.pki.KeyStoreService;
import uk.gov.dbt.ndtp.federator.certificate.manager.service.pki.VaultSecretProvider;
import uk.gov.dbt.ndtp.federator.certificate.manager.service.pki.cryptography.PemUtil;

@ExtendWith(MockitoExtension.class)
class KeyStoreSyncServiceImplTest {

    @TempDir
    Path tempDir;

    @Mock
    private VaultSecretProvider vaultSecretProvider;

    @Mock
    private KeyStoreService keyStoreService;

    @Mock
    private PoolingHttpClientConnectionManager connectionManager;

    private FileSystemServiceImpl realFileSystemService;

    private CertificateProperties certificateProperties;
    private KeyStoreSyncServiceImpl keyStoreSyncService;

    private String certPem;
    private String privateKeyPem;
    private String caPem;
    private byte[] validKeystoreBytes;
    private byte[] validTruststoreBytes;
    private KeyStoreService realKeyStoreService;
    private KeyPair caKeyPair;

    @BeforeEach
    void setUp() throws Exception {
        realFileSystemService = new FileSystemServiceImpl();
        certificateProperties = new CertificateProperties();
        CertificateProperties.Destination dest = certificateProperties.getDestination();
        dest.setKeystorePassword("ks-pass");
        dest.setTruststorePassword("ts-pass");
        CertificateProperties.StoreLocation file = new CertificateProperties.StoreLocation();
        file.setPath(tempDir.toString());
        file.setKeystoreFile("keystore.p12");
        file.setTruststoreFile("truststore.p12");
        file.setKeystoreAlias("federator");
        dest.setFile(file);

        keyStoreSyncService = new KeyStoreSyncServiceImpl(
                certificateProperties, vaultSecretProvider, keyStoreService, realFileSystemService);

        // Generate test certs and real keystore bytes
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        caKeyPair = kpg.generateKeyPair();
        KeyPair leafKeyPair = kpg.generateKeyPair();

        X500Name caName = new X500Name("CN=CA");
        X500Name leafName = new X500Name("CN=Leaf");
        long now = System.currentTimeMillis();
        Date start = new Date(now);
        Date end = new Date(now + 1000000);
        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA").build(caKeyPair.getPrivate());

        X509v3CertificateBuilder caBuilder = new JcaX509v3CertificateBuilder(
                caName, BigInteger.valueOf(now), start, end, caName, caKeyPair.getPublic());
        X509Certificate caCert = new JcaX509CertificateConverter().getCertificate(caBuilder.build(signer));
        caPem = PemUtil.toPem("CERTIFICATE", caCert.getEncoded());

        X509v3CertificateBuilder leafBuilder = new JcaX509v3CertificateBuilder(
                caName, BigInteger.valueOf(now + 1), start, end, leafName, leafKeyPair.getPublic());
        X509Certificate leafCert = new JcaX509CertificateConverter().getCertificate(leafBuilder.build(signer));
        certPem = PemUtil.toPem("CERTIFICATE", leafCert.getEncoded());
        privateKeyPem = PemUtil.toPem("PRIVATE KEY", leafKeyPair.getPrivate().getEncoded());

        // Build real PKCS12 bytes for validation to pass
        realKeyStoreService = new KeyStoreService();
        validKeystoreBytes =
                realKeyStoreService.createKeyStore(privateKeyPem, certPem, List.of(caPem), "ks-pass", "federator");
        Path trustStorePath = tempDir.resolve("truststore.p12");
        validTruststoreBytes = realKeyStoreService.createTrustStore(List.of(caPem), "ts-pass", trustStorePath);
    }

    // --- syncKeyStores ---

    @Test
    void syncKeyStores_createsKeystoreAndTruststore() {
        CreateKeyResponseDTO keyPair = CreateKeyResponseDTO.builder()
                .publicKeyPem("pub")
                .privateKeyPem(privateKeyPem)
                .build();

        when(vaultSecretProvider.getCertificate()).thenReturn(certPem);
        when(vaultSecretProvider.getKeyPair()).thenReturn(keyPair);
        when(vaultSecretProvider.getCaChain()).thenReturn(List.of(caPem));
        when(keyStoreService.createKeyStore(anyString(), anyString(), any(), anyString(), anyString()))
                .thenReturn(validKeystoreBytes);
        when(keyStoreService.createTrustStore(any(), anyString(), any())).thenReturn(validTruststoreBytes);

        keyStoreSyncService.syncKeyStores();

        assertTrue(Files.exists(tempDir.resolve("keystore.p12")));
        assertTrue(Files.exists(tempDir.resolve("truststore.p12")));
        assertTrue(Files.exists(tempDir.resolve("keystore.password")));
        assertTrue(Files.exists(tempDir.resolve("truststore.password")));
    }

    @Test
    void syncKeyStores_skipsUpdateWhenInSync() throws Exception {
        Files.write(tempDir.resolve("keystore.p12"), validKeystoreBytes);
        Files.write(tempDir.resolve("truststore.p12"), validTruststoreBytes);
        Files.write(tempDir.resolve("keystore.password"), "ks-pass".getBytes());
        Files.write(tempDir.resolve("truststore.password"), "ts-pass".getBytes());

        CreateKeyResponseDTO keyPair = CreateKeyResponseDTO.builder()
                .publicKeyPem("pub")
                .privateKeyPem(privateKeyPem)
                .build();

        when(vaultSecretProvider.getCertificate()).thenReturn(certPem);
        when(vaultSecretProvider.getKeyPair()).thenReturn(keyPair);
        when(vaultSecretProvider.getCaChain()).thenReturn(List.of(caPem));

        keyStoreSyncService.syncKeyStores();

        verify(keyStoreService, never()).createKeyStore(any(), any(), any(), any(), any());
        verify(keyStoreService, never()).createTrustStore(any(), any(), any());
    }

    @Test
    void syncKeyStores_skipsWhenNoCertificate() {
        when(vaultSecretProvider.getCertificate()).thenReturn(null);
        when(vaultSecretProvider.getKeyPair()).thenReturn(null);
        when(vaultSecretProvider.getCaChain()).thenReturn(List.of());

        keyStoreSyncService.syncKeyStores();

        verify(keyStoreService, never()).createKeyStore(any(), any(), any(), any(), any());
        verify(keyStoreService, never()).createTrustStore(any(), any(), any());
    }

    @Test
    void syncKeyStores_fallsBackToIntermediateCaWhenCaChainEmpty() {
        CreateKeyResponseDTO keyPair = CreateKeyResponseDTO.builder()
                .publicKeyPem("pub")
                .privateKeyPem(privateKeyPem)
                .build();

        when(vaultSecretProvider.getCertificate()).thenReturn(certPem);
        when(vaultSecretProvider.getKeyPair()).thenReturn(keyPair);
        when(vaultSecretProvider.getCaChain()).thenReturn(List.of());
        when(vaultSecretProvider.getIntermediateCa()).thenReturn(caPem);
        when(keyStoreService.createKeyStore(anyString(), anyString(), any(), anyString(), anyString()))
                .thenReturn(validKeystoreBytes);
        when(keyStoreService.createTrustStore(any(), anyString(), any())).thenReturn(validTruststoreBytes);

        keyStoreSyncService.syncKeyStores();

        verify(keyStoreService).createTrustStore(eq(List.of(caPem)), anyString(), any());
    }

    @Test
    void syncKeyStores_fallsBackToIntermediateCaWhenCaChainNull() {
        CreateKeyResponseDTO keyPair = CreateKeyResponseDTO.builder()
                .publicKeyPem("pub")
                .privateKeyPem(privateKeyPem)
                .build();

        when(vaultSecretProvider.getCertificate()).thenReturn(certPem);
        when(vaultSecretProvider.getKeyPair()).thenReturn(keyPair);
        when(vaultSecretProvider.getCaChain()).thenReturn(null);
        when(vaultSecretProvider.getIntermediateCa()).thenReturn(caPem);
        when(keyStoreService.createKeyStore(anyString(), anyString(), any(), anyString(), anyString()))
                .thenReturn(validKeystoreBytes);
        when(keyStoreService.createTrustStore(any(), anyString(), any())).thenReturn(validTruststoreBytes);

        keyStoreSyncService.syncKeyStores();

        verify(keyStoreService).createTrustStore(eq(List.of(caPem)), anyString(), any());
    }

    @Test
    void syncKeyStores_skipsTruststoreWhenNoCaChainAndNoIntermediateCa() {
        CreateKeyResponseDTO keyPair = CreateKeyResponseDTO.builder()
                .publicKeyPem("pub")
                .privateKeyPem(privateKeyPem)
                .build();

        when(vaultSecretProvider.getCertificate()).thenReturn(certPem);
        when(vaultSecretProvider.getKeyPair()).thenReturn(keyPair);
        when(vaultSecretProvider.getCaChain()).thenReturn(List.of());
        when(vaultSecretProvider.getIntermediateCa()).thenReturn(null);
        when(keyStoreService.createKeyStore(anyString(), anyString(), any(), anyString(), anyString()))
                .thenReturn(validKeystoreBytes);

        keyStoreSyncService.syncKeyStores();

        verify(keyStoreService, never()).createTrustStore(any(), any(), any());
    }

    @Test
    void syncKeyStores_handlesCorruptExistingKeystore() throws Exception {
        Files.write(tempDir.resolve("keystore.p12"), "corrupt data".getBytes());

        CreateKeyResponseDTO keyPair = CreateKeyResponseDTO.builder()
                .publicKeyPem("pub")
                .privateKeyPem(privateKeyPem)
                .build();

        when(vaultSecretProvider.getCertificate()).thenReturn(certPem);
        when(vaultSecretProvider.getKeyPair()).thenReturn(keyPair);
        when(vaultSecretProvider.getCaChain()).thenReturn(List.of(caPem));
        when(keyStoreService.createKeyStore(anyString(), anyString(), any(), anyString(), anyString()))
                .thenReturn(validKeystoreBytes);
        when(keyStoreService.createTrustStore(any(), anyString(), any())).thenReturn(validTruststoreBytes);

        keyStoreSyncService.syncKeyStores();

        verify(keyStoreService).createKeyStore(anyString(), anyString(), any(), anyString(), anyString());
    }

    @Test
    void syncKeyStores_handlesCorruptExistingTruststore() throws Exception {
        Files.write(tempDir.resolve("truststore.p12"), "corrupt data".getBytes());

        CreateKeyResponseDTO keyPair = CreateKeyResponseDTO.builder()
                .publicKeyPem("pub")
                .privateKeyPem(privateKeyPem)
                .build();

        when(vaultSecretProvider.getCertificate()).thenReturn(certPem);
        when(vaultSecretProvider.getKeyPair()).thenReturn(keyPair);
        when(vaultSecretProvider.getCaChain()).thenReturn(List.of(caPem));
        when(keyStoreService.createKeyStore(anyString(), anyString(), any(), anyString(), anyString()))
                .thenReturn(validKeystoreBytes);
        when(keyStoreService.createTrustStore(any(), anyString(), any())).thenReturn(validTruststoreBytes);

        keyStoreSyncService.syncKeyStores();

        verify(keyStoreService).createTrustStore(any(), anyString(), any());
    }

    @Test
    void syncKeyStores_skipsWhenNoPrivateKey() {
        CreateKeyResponseDTO keyPair =
                CreateKeyResponseDTO.builder().publicKeyPem("pub").build();

        when(vaultSecretProvider.getCertificate()).thenReturn(certPem);
        when(vaultSecretProvider.getKeyPair()).thenReturn(keyPair);
        when(vaultSecretProvider.getCaChain()).thenReturn(List.of(caPem));
        when(keyStoreService.createTrustStore(any(), anyString(), any())).thenReturn(validTruststoreBytes);

        keyStoreSyncService.syncKeyStores();

        verify(keyStoreService, never()).createKeyStore(any(), any(), any(), any(), any());
        verify(keyStoreService).createTrustStore(any(), anyString(), any());
    }

    @Test
    void syncKeyStores_updatesWhenCaChainDiffers() throws Exception {
        Files.write(tempDir.resolve("truststore.p12"), validTruststoreBytes);
        Files.write(tempDir.resolve("truststore.password"), "ts-pass".getBytes());

        when(vaultSecretProvider.getCertificate()).thenReturn(null);
        when(vaultSecretProvider.getKeyPair()).thenReturn(null);
        when(vaultSecretProvider.getCaChain()).thenReturn(List.of(caPem, caPem));
        Path trustStorePath = tempDir.resolve("truststore.p12");
        byte[] newTruststoreBytes =
                realKeyStoreService.createTrustStore(List.of(caPem, caPem), "ts-pass", trustStorePath);
        when(keyStoreService.createTrustStore(any(), anyString(), any())).thenReturn(newTruststoreBytes);

        keyStoreSyncService.syncKeyStores();

        verify(keyStoreService).createTrustStore(any(), anyString(), any());
    }

    @Test
    void syncKeyStores_passwordFileAlreadyInSync() throws Exception {
        Files.write(tempDir.resolve("keystore.password"), "ks-pass".getBytes());
        Files.write(tempDir.resolve("truststore.password"), "ts-pass".getBytes());

        CreateKeyResponseDTO keyPair = CreateKeyResponseDTO.builder()
                .publicKeyPem("pub")
                .privateKeyPem(privateKeyPem)
                .build();

        when(vaultSecretProvider.getCertificate()).thenReturn(certPem);
        when(vaultSecretProvider.getKeyPair()).thenReturn(keyPair);
        when(vaultSecretProvider.getCaChain()).thenReturn(List.of(caPem));
        when(keyStoreService.createKeyStore(anyString(), anyString(), any(), anyString(), anyString()))
                .thenReturn(validKeystoreBytes);
        when(keyStoreService.createTrustStore(any(), anyString(), any())).thenReturn(validTruststoreBytes);

        keyStoreSyncService.syncKeyStores();

        assertTrue(Files.exists(tempDir.resolve("keystore.password")));
        assertTrue(Files.exists(tempDir.resolve("truststore.password")));
    }

    @Test
    void syncKeyStores_handlesEmptyCaChainInKeystore() {
        CreateKeyResponseDTO keyPair = CreateKeyResponseDTO.builder()
                .publicKeyPem("pub")
                .privateKeyPem(privateKeyPem)
                .build();
        byte[] ksNoCaChain = realKeyStoreService.createKeyStore(
                privateKeyPem, certPem, Collections.emptyList(), "ks-pass", "federator");

        when(vaultSecretProvider.getCertificate()).thenReturn(certPem);
        when(vaultSecretProvider.getKeyPair()).thenReturn(keyPair);
        when(vaultSecretProvider.getCaChain()).thenReturn(Collections.emptyList());
        when(vaultSecretProvider.getIntermediateCa()).thenReturn(null);
        when(keyStoreService.createKeyStore(anyString(), anyString(), any(), anyString(), anyString()))
                .thenReturn(ksNoCaChain);

        keyStoreSyncService.syncKeyStores();

        verify(keyStoreService).createKeyStore(anyString(), anyString(), any(), anyString(), anyString());
    }

    // --- validateKeyStore: KeyStoreCreationException ---

    @Test
    void syncKeyStores_throwsKeyStoreCreationExceptionForInvalidKeystoreBytes() {
        CreateKeyResponseDTO keyPair = CreateKeyResponseDTO.builder()
                .publicKeyPem("pub")
                .privateKeyPem(privateKeyPem)
                .build();

        when(vaultSecretProvider.getCertificate()).thenReturn(certPem);
        when(vaultSecretProvider.getKeyPair()).thenReturn(keyPair);
        when(vaultSecretProvider.getCaChain()).thenReturn(List.of(caPem));
        when(keyStoreService.createKeyStore(anyString(), anyString(), any(), anyString(), anyString()))
                .thenReturn(new byte[] {0x00, 0x01, 0x02});

        KeyStoreCreationException ex = assertThrows(KeyStoreCreationException.class, () -> {
            keyStoreSyncService.syncKeyStores();
        });

        assertEquals("Failed to validate generated keystore", ex.getMessage());
        assertNotNull(ex.getCause());
    }

    @Test
    void syncKeyStores_throwsKeyStoreCreationExceptionWhenAliasMissing() {
        CreateKeyResponseDTO keyPair = CreateKeyResponseDTO.builder()
                .publicKeyPem("pub")
                .privateKeyPem(privateKeyPem)
                .build();

        // Build a keystore with a different alias so "federator" is missing
        byte[] wrongAliasKeystore =
                realKeyStoreService.createKeyStore(privateKeyPem, certPem, List.of(caPem), "ks-pass", "wrong-alias");

        when(vaultSecretProvider.getCertificate()).thenReturn(certPem);
        when(vaultSecretProvider.getKeyPair()).thenReturn(keyPair);
        when(vaultSecretProvider.getCaChain()).thenReturn(List.of(caPem));
        when(keyStoreService.createKeyStore(anyString(), anyString(), any(), anyString(), anyString()))
                .thenReturn(wrongAliasKeystore);

        KeyStoreCreationException ex = assertThrows(KeyStoreCreationException.class, () -> {
            keyStoreSyncService.syncKeyStores();
        });

        assertTrue(ex.getMessage().contains("Generated keystore missing expected alias: federator"));
        assertNull(ex.getCause());
    }

    // --- validateTrustStore: KeyStoreCreationException ---

    @Test
    void syncKeyStores_throwsKeyStoreCreationExceptionForInvalidTruststoreBytes() {
        when(vaultSecretProvider.getCertificate()).thenReturn(null);
        when(vaultSecretProvider.getKeyPair()).thenReturn(null);
        when(vaultSecretProvider.getCaChain()).thenReturn(List.of(caPem));
        when(keyStoreService.createTrustStore(any(), anyString(), any())).thenReturn(new byte[] {0x00, 0x01, 0x02});

        KeyStoreCreationException ex = assertThrows(KeyStoreCreationException.class, () -> {
            keyStoreSyncService.syncKeyStores();
        });

        assertEquals("Failed to validate generated truststore", ex.getMessage());
        assertNotNull(ex.getCause());
    }

    // --- writePasswordToFile: FileSystemException ---

    @Test
    void syncKeyStores_propagatesFileSystemExceptionFromPasswordWrite() {
        FileSystemService mockFs = mock(FileSystemService.class);
        KeyStoreSyncServiceImpl serviceWithMockFs =
                new KeyStoreSyncServiceImpl(certificateProperties, vaultSecretProvider, keyStoreService, mockFs);

        CreateKeyResponseDTO keyPair = CreateKeyResponseDTO.builder()
                .publicKeyPem("pub")
                .privateKeyPem(privateKeyPem)
                .build();

        when(vaultSecretProvider.getCertificate()).thenReturn(certPem);
        when(vaultSecretProvider.getKeyPair()).thenReturn(keyPair);
        when(vaultSecretProvider.getCaChain()).thenReturn(List.of(caPem));
        when(keyStoreService.createKeyStore(anyString(), anyString(), any(), anyString(), anyString()))
                .thenReturn(validKeystoreBytes);
        when(mockFs.needsUpdate(any(), any())).thenReturn(true);
        doNothing().when(mockFs).atomicWrite(any(), any());
        doThrow(new FileSystemException("disk full")).when(mockFs).write(any(), any());

        FileSystemException ex = assertThrows(FileSystemException.class, serviceWithMockFs::syncKeyStores);

        assertEquals("disk full", ex.getMessage());
    }

    // --- shouldUpdateKeyStore edge cases ---

    @Test
    void syncKeyStores_updatesWhenExistingKeystoreHasDifferentKey() throws Exception {
        // Write a keystore with a different key pair
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        KeyPair differentKeyPair = kpg.generateKeyPair();
        String differentPrivateKeyPem =
                PemUtil.toPem("PRIVATE KEY", differentKeyPair.getPrivate().getEncoded());

        byte[] existingKs = realKeyStoreService.createKeyStore(
                differentPrivateKeyPem, certPem, List.of(caPem), "ks-pass", "federator");
        Files.write(tempDir.resolve("keystore.p12"), existingKs);

        CreateKeyResponseDTO keyPair = CreateKeyResponseDTO.builder()
                .publicKeyPem("pub")
                .privateKeyPem(privateKeyPem)
                .build();

        when(vaultSecretProvider.getCertificate()).thenReturn(certPem);
        when(vaultSecretProvider.getKeyPair()).thenReturn(keyPair);
        when(vaultSecretProvider.getCaChain()).thenReturn(List.of(caPem));
        when(keyStoreService.createKeyStore(anyString(), anyString(), any(), anyString(), anyString()))
                .thenReturn(validKeystoreBytes);
        when(keyStoreService.createTrustStore(any(), anyString(), any())).thenReturn(validTruststoreBytes);

        keyStoreSyncService.syncKeyStores();

        verify(keyStoreService).createKeyStore(anyString(), anyString(), any(), anyString(), anyString());
    }

    @Test
    void syncKeyStores_updatesWhenExistingKeystoreHasDifferentChainLength() throws Exception {
        // Existing keystore has no CA chain, new one has one
        byte[] existingKs = realKeyStoreService.createKeyStore(
                privateKeyPem, certPem, Collections.emptyList(), "ks-pass", "federator");
        Files.write(tempDir.resolve("keystore.p12"), existingKs);

        CreateKeyResponseDTO keyPair = CreateKeyResponseDTO.builder()
                .publicKeyPem("pub")
                .privateKeyPem(privateKeyPem)
                .build();

        when(vaultSecretProvider.getCertificate()).thenReturn(certPem);
        when(vaultSecretProvider.getKeyPair()).thenReturn(keyPair);
        when(vaultSecretProvider.getCaChain()).thenReturn(List.of(caPem));
        when(keyStoreService.createKeyStore(anyString(), anyString(), any(), anyString(), anyString()))
                .thenReturn(validKeystoreBytes);
        when(keyStoreService.createTrustStore(any(), anyString(), any())).thenReturn(validTruststoreBytes);

        keyStoreSyncService.syncKeyStores();

        verify(keyStoreService).createKeyStore(anyString(), anyString(), any(), anyString(), anyString());
    }

    // --- shouldUpdateTrustStore edge cases ---

    @Test
    void syncKeyStores_updatesWhenTruststoreHasDifferentCert() throws Exception {
        // Generate a different CA cert
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        KeyPair differentCaKeyPair = kpg.generateKeyPair();
        X500Name differentCaName = new X500Name("CN=DifferentCA");
        long now = System.currentTimeMillis();
        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA").build(differentCaKeyPair.getPrivate());
        X509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                differentCaName,
                BigInteger.valueOf(now + 99),
                new Date(now),
                new Date(now + 1000000),
                differentCaName,
                differentCaKeyPair.getPublic());
        X509Certificate differentCaCert = new JcaX509CertificateConverter().getCertificate(builder.build(signer));
        String differentCaPem = PemUtil.toPem("CERTIFICATE", differentCaCert.getEncoded());

        // Write truststore with the different CA
        Path trustStorePath = tempDir.resolve("truststore.p12");
        byte[] existingTs = realKeyStoreService.createTrustStore(List.of(differentCaPem), "ts-pass", trustStorePath);
        Files.write(tempDir.resolve("truststore.p12"), existingTs);

        when(vaultSecretProvider.getCertificate()).thenReturn(null);
        when(vaultSecretProvider.getKeyPair()).thenReturn(null);
        when(vaultSecretProvider.getCaChain()).thenReturn(List.of(caPem));
        when(keyStoreService.createTrustStore(any(), anyString(), any())).thenReturn(validTruststoreBytes);

        keyStoreSyncService.syncKeyStores();

        verify(keyStoreService).createTrustStore(any(), anyString(), any());
    }

    @Test
    void syncKeyStores_updatesWhenTruststoreMissingAlias() throws Exception {
        // Create a truststore with a non-standard alias scheme
        java.security.KeyStore ks = java.security.KeyStore.getInstance("PKCS12");
        ks.load(null, "ts-pass".toCharArray());
        X509Certificate caCert = PemUtil.parseCertificate(caPem);
        ks.setCertificateEntry("nonstandard-alias", caCert);
        java.io.ByteArrayOutputStream baos = new java.io.ByteArrayOutputStream();
        ks.store(baos, "ts-pass".toCharArray());
        Files.write(tempDir.resolve("truststore.p12"), baos.toByteArray());

        when(vaultSecretProvider.getCertificate()).thenReturn(null);
        when(vaultSecretProvider.getKeyPair()).thenReturn(null);
        when(vaultSecretProvider.getCaChain()).thenReturn(List.of(caPem));
        when(keyStoreService.createTrustStore(any(), anyString(), any())).thenReturn(validTruststoreBytes);

        keyStoreSyncService.syncKeyStores();

        verify(keyStoreService).createTrustStore(any(), anyString(), any());
    }

    // --- resolvePassword ---

    @Test
    void resolvePassword_usesConfiguredPassword() {
        String result = keyStoreSyncService.resolvePassword("configured-pass", "suffix");
        assertEquals("configured-pass", result);
        verify(vaultSecretProvider, never()).getSecret(any());
    }

    @ParameterizedTest
    @NullAndEmptySource
    @ValueSource(strings = {"  "})
    void resolvePassword_fetchesFromVault(String configuredPassword) {
        when(vaultSecretProvider.getSecret("suffix")).thenReturn(Map.of("password", "vault-pass"));

        String result = keyStoreSyncService.resolvePassword(configuredPassword, "suffix");
        assertEquals("vault-pass", result);
    }

    @Test
    void resolvePassword_generatesNewPassword() {
        when(vaultSecretProvider.getSecret("suffix")).thenReturn(Collections.emptyMap());

        String result = keyStoreSyncService.resolvePassword(null, "suffix");
        assertNotNull(result);
        assertFalse(result.isBlank());
        verify(vaultSecretProvider).persistSecret(eq("suffix"), any());
    }

    @Test
    void resolvePassword_generatesWhenVaultSecretHasNoPasswordKey() {
        when(vaultSecretProvider.getSecret("suffix")).thenReturn(Map.of("other", "value"));

        String result = keyStoreSyncService.resolvePassword(null, "suffix");
        assertNotNull(result);
        assertFalse(result.isBlank());
        verify(vaultSecretProvider).persistSecret(eq("suffix"), any());
    }

    // --- writePasswordToFile with null parent path ---

    @Test
    void syncKeyStores_writesPasswordWhenStorePathHasNoParent() {
        // Use a destination with a relative file name that has no parent
        certificateProperties.getDestination().getFile().setPath(tempDir.toString());

        CreateKeyResponseDTO keyPair = CreateKeyResponseDTO.builder()
                .publicKeyPem("pub")
                .privateKeyPem(privateKeyPem)
                .build();

        when(vaultSecretProvider.getCertificate()).thenReturn(certPem);
        when(vaultSecretProvider.getKeyPair()).thenReturn(keyPair);
        when(vaultSecretProvider.getCaChain()).thenReturn(List.of(caPem));
        when(keyStoreService.createKeyStore(anyString(), anyString(), any(), anyString(), anyString()))
                .thenReturn(validKeystoreBytes);
        when(keyStoreService.createTrustStore(any(), anyString(), any())).thenReturn(validTruststoreBytes);

        assertDoesNotThrow(() -> keyStoreSyncService.syncKeyStores());
    }

    // --- password resolution during sync (no configured password) ---

    @Test
    void syncKeyStores_resolvesPasswordFromVaultWhenNotConfigured() {
        CertificateProperties.Destination dest = certificateProperties.getDestination();
        dest.setKeystorePassword(null);
        dest.setTruststorePassword(null);

        when(vaultSecretProvider.getSecret("keystore-password")).thenReturn(Map.of("password", "vault-ks-pass"));
        when(vaultSecretProvider.getSecret("truststore-password")).thenReturn(Map.of("password", "vault-ts-pass"));

        CreateKeyResponseDTO keyPair = CreateKeyResponseDTO.builder()
                .publicKeyPem("pub")
                .privateKeyPem(privateKeyPem)
                .build();

        when(vaultSecretProvider.getCertificate()).thenReturn(certPem);
        when(vaultSecretProvider.getKeyPair()).thenReturn(keyPair);
        when(vaultSecretProvider.getCaChain()).thenReturn(List.of(caPem));

        byte[] ksBytes = realKeyStoreService.createKeyStore(
                privateKeyPem, certPem, List.of(caPem), "vault-ks-pass", "federator");
        Path trustStorePath = tempDir.resolve("truststore.p12");
        byte[] tsBytes = realKeyStoreService.createTrustStore(List.of(caPem), "vault-ts-pass", trustStorePath);
        when(keyStoreService.createKeyStore(anyString(), anyString(), any(), anyString(), anyString()))
                .thenReturn(ksBytes);
        when(keyStoreService.createTrustStore(any(), anyString(), any())).thenReturn(tsBytes);

        keyStoreSyncService.syncKeyStores();

        assertTrue(Files.exists(tempDir.resolve("keystore.p12")));
        assertTrue(Files.exists(tempDir.resolve("truststore.p12")));
    }

    @Test
    void syncKeyStores_generatesAndPersistsPasswordWhenNotInVault() {
        CertificateProperties.Destination dest = certificateProperties.getDestination();
        dest.setKeystorePassword(null);
        dest.setTruststorePassword(null);

        when(vaultSecretProvider.getSecret("keystore-password")).thenReturn(Collections.emptyMap());
        when(vaultSecretProvider.getSecret("truststore-password")).thenReturn(Collections.emptyMap());

        when(vaultSecretProvider.getCertificate()).thenReturn(null);
        when(vaultSecretProvider.getKeyPair()).thenReturn(null);
        when(vaultSecretProvider.getCaChain()).thenReturn(List.of());
        when(vaultSecretProvider.getIntermediateCa()).thenReturn(null);

        keyStoreSyncService.syncKeyStores();

        verify(vaultSecretProvider).persistSecret(eq("keystore-password"), any());
        verify(vaultSecretProvider).persistSecret(eq("truststore-password"), any());
    }

    // --- destination selection and Vault destination ---

    private static final String VAULT_PATH = "/secret/app/federator";

    private CertificateProperties.StoreLocation vaultLocation() {
        CertificateProperties.StoreLocation vault = new CertificateProperties.StoreLocation();
        vault.setPath(VAULT_PATH);
        vault.setKeystoreFile("keystore.p12");
        vault.setTruststoreFile("truststore.p12");
        vault.setKeystoreAlias("federator");
        return vault;
    }

    private static final Instant NOW = Instant.parse("2026-10-22T09:30:00Z");

    private KeyStoreSyncServiceImpl serviceWithRealStores() {
        return serviceWithRealStores(NOW);
    }

    private KeyStoreSyncServiceImpl serviceWithRealStores(Instant now) {
        KeyStoreSyncServiceImpl service = new KeyStoreSyncServiceImpl(
                certificateProperties, vaultSecretProvider, realKeyStoreService, realFileSystemService);
        service.setClock(Clock.fixed(now, ZoneOffset.UTC));
        return service;
    }

    private void stubCertificateMaterial(String certificate, String privateKey) {
        when(vaultSecretProvider.getCertificate()).thenReturn(certificate);
        when(vaultSecretProvider.getKeyPair())
                .thenReturn(CreateKeyResponseDTO.builder()
                        .publicKeyPem("pub")
                        .privateKeyPem(privateKey)
                        .build());
        when(vaultSecretProvider.getCaChain()).thenReturn(List.of(caPem));
    }

    private Map<String, Object> inSyncVaultSecret() {
        Map<String, Object> secret = new HashMap<>();
        secret.put(
                "keystore.p12",
                Base64.getEncoder()
                        .encodeToString(realKeyStoreService.createKeyStore(
                                privateKeyPem, certPem, List.of(caPem), "ks-pass", "federator")));
        secret.put(
                "truststore.p12",
                Base64.getEncoder()
                        .encodeToString(realKeyStoreService.createTrustStore(List.of(caPem), "ts-pass", null)));
        secret.put("keystore.password", "ks-pass");
        secret.put("truststore.password", "ts-pass");
        secret.put("createdAt", "2026-10-01T08:00:00Z");
        secret.put("updatedAt", "2026-10-01T08:00:00Z");
        return secret;
    }

    @SuppressWarnings("unchecked")
    private Map<String, String> capturePersistedVaultSecret() {
        ArgumentCaptor<Map<String, String>> captor = ArgumentCaptor.forClass(Map.class);
        verify(vaultSecretProvider).persistSecretAtPath(eq(VAULT_PATH), captor.capture());
        return captor.getValue();
    }

    private static KeyStore loadBase64Store(String base64, String password) throws Exception {
        KeyStore ks = KeyStore.getInstance("PKCS12");
        ks.load(new ByteArrayInputStream(Base64.getDecoder().decode(base64)), password.toCharArray());
        return ks;
    }

    @Test
    void syncKeyStores_skipsWhenNoDestinationConfigured() {
        certificateProperties.getDestination().setFile(null);
        certificateProperties.getDestination().setVault(null);

        keyStoreSyncService.syncKeyStores();

        verifyNoInteractions(vaultSecretProvider, keyStoreService);
    }

    @ParameterizedTest
    @NullAndEmptySource
    @ValueSource(strings = {"  "})
    void syncKeyStores_treatsBlankPathAsNotConfigured(String path) {
        certificateProperties.getDestination().getFile().setPath(path);
        CertificateProperties.StoreLocation vault = vaultLocation();
        vault.setPath(path);
        certificateProperties.getDestination().setVault(vault);

        keyStoreSyncService.syncKeyStores();

        verifyNoInteractions(vaultSecretProvider, keyStoreService);
    }

    @Test
    void syncKeyStores_vaultOnly_writesStoresAndPasswordsToVaultAndNoFiles() throws Exception {
        certificateProperties.getDestination().setFile(null);
        certificateProperties.getDestination().setVault(vaultLocation());
        stubCertificateMaterial(certPem, privateKeyPem);
        when(vaultSecretProvider.getSecretAtPath(VAULT_PATH)).thenReturn(Map.of());

        serviceWithRealStores().syncKeyStores();

        Map<String, String> secret = capturePersistedVaultSecret();
        assertEquals("ks-pass", secret.get("keystore.password"));
        assertEquals("ts-pass", secret.get("truststore.password"));
        KeyStore keystore = loadBase64Store(secret.get("keystore.p12"), "ks-pass");
        assertTrue(keystore.isKeyEntry("federator"));
        assertEquals(PemUtil.parseCertificate(certPem), keystore.getCertificateChain("federator")[0]);
        KeyStore truststore = loadBase64Store(secret.get("truststore.p12"), "ts-pass");
        assertEquals(PemUtil.parseCertificate(caPem), truststore.getCertificate("ca-0"));
        try (var files = Files.list(tempDir)) {
            assertEquals(0, files.count());
        }
    }

    @Test
    void syncKeyStores_fileAndVault_writesBothDestinations() {
        certificateProperties.getDestination().setVault(vaultLocation());
        stubCertificateMaterial(certPem, privateKeyPem);
        when(vaultSecretProvider.getSecretAtPath(VAULT_PATH)).thenReturn(Map.of());

        serviceWithRealStores().syncKeyStores();

        assertTrue(Files.exists(tempDir.resolve("keystore.p12")));
        assertTrue(Files.exists(tempDir.resolve("truststore.p12")));
        assertTrue(Files.exists(tempDir.resolve("keystore.password")));
        assertTrue(Files.exists(tempDir.resolve("truststore.password")));
        Map<String, String> secret = capturePersistedVaultSecret();
        assertTrue(secret.keySet()
                .containsAll(List.of("keystore.p12", "truststore.p12", "keystore.password", "truststore.password")));
    }

    @Test
    void syncKeyStores_vault_usesConfiguredAttributeNamesAndAlias() throws Exception {
        certificateProperties.getDestination().setFile(null);
        CertificateProperties.StoreLocation vault = vaultLocation();
        vault.setKeystoreFile("ks");
        vault.setTruststoreFile("ts");
        vault.setKeystoreAlias("custom-alias");
        certificateProperties.getDestination().setVault(vault);
        stubCertificateMaterial(certPem, privateKeyPem);
        when(vaultSecretProvider.getSecretAtPath(VAULT_PATH)).thenReturn(Map.of());

        serviceWithRealStores().syncKeyStores();

        Map<String, String> secret = capturePersistedVaultSecret();
        assertEquals(
                Set.of("ks", "ts", "keystore.password", "truststore.password", "createdAt", "updatedAt"),
                secret.keySet());
        assertTrue(loadBase64Store(secret.get("ks"), "ks-pass").isKeyEntry("custom-alias"));
    }

    @Test
    void syncKeyStores_vault_skipsWriteWhenAlreadyInSync() {
        certificateProperties.getDestination().setFile(null);
        certificateProperties.getDestination().setVault(vaultLocation());
        stubCertificateMaterial(certPem, privateKeyPem);
        when(vaultSecretProvider.getSecretAtPath(VAULT_PATH)).thenReturn(inSyncVaultSecret());

        serviceWithRealStores().syncKeyStores();

        verify(vaultSecretProvider, never()).persistSecretAtPath(anyString(), any());
    }

    @Test
    void syncKeyStores_vault_updatesSecretAfterRotation() throws Exception {
        certificateProperties.getDestination().setFile(null);
        certificateProperties.getDestination().setVault(vaultLocation());
        // Vault destination holds the stores for the current certificate; a new key and certificate are issued
        when(vaultSecretProvider.getSecretAtPath(VAULT_PATH)).thenReturn(inSyncVaultSecret());
        KeyPair rotatedKeyPair = newKeyPair();
        X509Certificate rotatedCert = issueCert("CN=Leaf", rotatedKeyPair.getPublic(), "CN=CA", caKeyPair);
        stubCertificateMaterial(
                PemUtil.toPem("CERTIFICATE", rotatedCert.getEncoded()),
                PemUtil.toPem("PRIVATE KEY", rotatedKeyPair.getPrivate().getEncoded()));

        serviceWithRealStores().syncKeyStores();

        Map<String, String> secret = capturePersistedVaultSecret();
        KeyStore keystore = loadBase64Store(secret.get("keystore.p12"), "ks-pass");
        assertEquals(rotatedCert, keystore.getCertificateChain("federator")[0]);
        assertArrayEquals(
                rotatedKeyPair.getPrivate().getEncoded(),
                keystore.getKey("federator", "ks-pass".toCharArray()).getEncoded());
    }

    @Test
    void syncKeyStores_vault_updatesSecretWhenCaChainChanges() throws Exception {
        certificateProperties.getDestination().setFile(null);
        certificateProperties.getDestination().setVault(vaultLocation());
        when(vaultSecretProvider.getSecretAtPath(VAULT_PATH)).thenReturn(inSyncVaultSecret());
        // CA re-issued with the same name and a new key
        KeyPair newCaKeyPair = newKeyPair();
        String newCaPem = PemUtil.toPem(
                "CERTIFICATE",
                issueCert("CN=CA", newCaKeyPair.getPublic(), "CN=CA", newCaKeyPair)
                        .getEncoded());
        stubCertificateMaterial(certPem, privateKeyPem);
        when(vaultSecretProvider.getCaChain()).thenReturn(List.of(newCaPem));

        serviceWithRealStores().syncKeyStores();

        Map<String, String> secret = capturePersistedVaultSecret();
        KeyStore truststore = loadBase64Store(secret.get("truststore.p12"), "ts-pass");
        assertEquals(1, truststore.size());
        assertEquals(PemUtil.parseCertificate(newCaPem), truststore.getCertificate("ca-0"));
    }

    @Test
    void syncKeyStores_vault_updatesSecretWhenPasswordAttributeIsStale() {
        certificateProperties.getDestination().setFile(null);
        certificateProperties.getDestination().setVault(vaultLocation());
        stubCertificateMaterial(certPem, privateKeyPem);
        Map<String, Object> existing = inSyncVaultSecret();
        existing.put("truststore.password", "stale");
        when(vaultSecretProvider.getSecretAtPath(VAULT_PATH)).thenReturn(existing);

        serviceWithRealStores().syncKeyStores();

        assertEquals("ts-pass", capturePersistedVaultSecret().get("truststore.password"));
    }

    @Test
    void syncKeyStores_vault_rewritesInvalidStoredValueAndKeepsUnrelatedAttributes() throws Exception {
        certificateProperties.getDestination().setFile(null);
        certificateProperties.getDestination().setVault(vaultLocation());
        stubCertificateMaterial(certPem, privateKeyPem);
        Map<String, Object> existing = inSyncVaultSecret();
        existing.put("keystore.p12", "not base64!");
        existing.put("owner", "platform-team");
        existing.put("version", 3);
        when(vaultSecretProvider.getSecretAtPath(VAULT_PATH)).thenReturn(existing);

        serviceWithRealStores().syncKeyStores();

        Map<String, String> secret = capturePersistedVaultSecret();
        assertTrue(loadBase64Store(secret.get("keystore.p12"), "ks-pass").isKeyEntry("federator"));
        assertEquals("platform-team", secret.get("owner"));
        assertFalse(secret.containsKey("version"));
    }

    @Test
    void syncKeyStores_vault_rewritesStoreThatCannotBeOpened() {
        certificateProperties.getDestination().setFile(null);
        certificateProperties.getDestination().setVault(vaultLocation());
        stubCertificateMaterial(certPem, privateKeyPem);
        Map<String, Object> existing = inSyncVaultSecret();
        existing.put("truststore.p12", Base64.getEncoder().encodeToString(new byte[] {1, 2, 3}));
        when(vaultSecretProvider.getSecretAtPath(VAULT_PATH)).thenReturn(existing);

        serviceWithRealStores().syncKeyStores();

        assertNotEquals(
                existing.get("truststore.p12"), capturePersistedVaultSecret().get("truststore.p12"));
    }

    @Test
    void syncKeyStores_vault_writesOnlyTruststoreWhenKeyPairMissing() {
        certificateProperties.getDestination().setFile(null);
        certificateProperties.getDestination().setVault(vaultLocation());
        when(vaultSecretProvider.getCertificate()).thenReturn(null);
        when(vaultSecretProvider.getKeyPair()).thenReturn(null);
        when(vaultSecretProvider.getCaChain()).thenReturn(List.of(caPem));
        when(vaultSecretProvider.getSecretAtPath(VAULT_PATH)).thenReturn(Map.of());

        serviceWithRealStores().syncKeyStores();

        assertEquals(
                Set.of("truststore.p12", "truststore.password", "createdAt", "updatedAt"),
                capturePersistedVaultSecret().keySet());
    }

    @Test
    void syncKeyStores_vault_skipsWhenNoCertificateMaterial() {
        certificateProperties.getDestination().setFile(null);
        certificateProperties.getDestination().setVault(vaultLocation());
        when(vaultSecretProvider.getCertificate()).thenReturn(null);
        when(vaultSecretProvider.getKeyPair()).thenReturn(null);
        when(vaultSecretProvider.getCaChain()).thenReturn(List.of());
        when(vaultSecretProvider.getIntermediateCa()).thenReturn(null);

        keyStoreSyncService.syncKeyStores();

        verify(vaultSecretProvider, never()).getSecretAtPath(anyString());
        verify(vaultSecretProvider, never()).persistSecretAtPath(anyString(), any());
    }

    private static KeyPair newKeyPair() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        return kpg.generateKeyPair();
    }

    private static X509Certificate issueCert(String subjectDn, PublicKey subjectKey, String issuerDn, KeyPair issuer)
            throws Exception {
        long now = System.currentTimeMillis();
        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA").build(issuer.getPrivate());
        X509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                new X500Name(issuerDn),
                BigInteger.valueOf(now + 7),
                new Date(now),
                new Date(now + 1000000),
                new X500Name(subjectDn),
                subjectKey);
        return new JcaX509CertificateConverter().getCertificate(builder.build(signer));
    }

    // --- key pair / certificate consistency ---

    @Test
    void syncKeyStores_skipsKeystoreWhenKeyPairDoesNotMatchCertificate() throws Exception {
        // e.g. the new key pair has been written but the new certificate not yet
        certificateProperties.getDestination().setVault(vaultLocation());
        String otherKeyPem =
                PemUtil.toPem("PRIVATE KEY", newKeyPair().getPrivate().getEncoded());
        stubCertificateMaterial(certPem, otherKeyPem);
        when(vaultSecretProvider.getSecretAtPath(VAULT_PATH)).thenReturn(Map.of());

        serviceWithRealStores().syncKeyStores();

        assertFalse(Files.exists(tempDir.resolve("keystore.p12")));
        assertFalse(Files.exists(tempDir.resolve("keystore.password")));
        assertTrue(Files.exists(tempDir.resolve("truststore.p12")));
        assertEquals(
                Set.of("truststore.p12", "truststore.password", "createdAt", "updatedAt"),
                capturePersistedVaultSecret().keySet());
    }

    @Test
    void syncKeyStores_keepsExistingKeystoreWhenKeyPairDoesNotMatchCertificate() throws Exception {
        Path keystorePath = tempDir.resolve("keystore.p12");
        Files.write(keystorePath, validKeystoreBytes);
        String otherKeyPem =
                PemUtil.toPem("PRIVATE KEY", newKeyPair().getPrivate().getEncoded());
        stubCertificateMaterial(certPem, otherKeyPem);

        serviceWithRealStores().syncKeyStores();

        assertArrayEquals(validKeystoreBytes, Files.readAllBytes(keystorePath));
    }

    // --- shared, auto-generated passwords ---

    @Test
    void syncKeyStores_generatesOnePasswordPairUsedByFileAndVault() throws Exception {
        CertificateProperties.Destination dest = certificateProperties.getDestination();
        dest.setKeystorePassword("");
        dest.setTruststorePassword(null);
        dest.setVault(vaultLocation());
        when(vaultSecretProvider.getSecret(anyString())).thenReturn(Map.of());
        stubCertificateMaterial(certPem, privateKeyPem);
        when(vaultSecretProvider.getSecretAtPath(VAULT_PATH)).thenReturn(Map.of());

        serviceWithRealStores().syncKeyStores();

        ArgumentCaptor<Map<String, String>> generated = ArgumentCaptor.forClass(Map.class);
        verify(vaultSecretProvider).persistSecret(eq("keystore-password"), generated.capture());
        String keystorePassword = generated.getValue().get("password");
        verify(vaultSecretProvider).persistSecret(eq("truststore-password"), generated.capture());
        String truststorePassword = generated.getValue().get("password");
        assertNotNull(keystorePassword);
        assertNotEquals(keystorePassword, truststorePassword);

        assertEquals(keystorePassword, Files.readString(tempDir.resolve("keystore.password")));
        assertEquals(truststorePassword, Files.readString(tempDir.resolve("truststore.password")));
        Map<String, String> secret = capturePersistedVaultSecret();
        assertEquals(keystorePassword, secret.get("keystore.password"));
        assertEquals(truststorePassword, secret.get("truststore.password"));
        assertTrue(loadBase64Store(secret.get("keystore.p12"), keystorePassword).isKeyEntry("federator"));
        KeyStore fileKeystore = KeyStore.getInstance("PKCS12");
        try (var in = Files.newInputStream(tempDir.resolve("keystore.p12"))) {
            fileKeystore.load(in, keystorePassword.toCharArray());
        }
        assertTrue(fileKeystore.isKeyEntry("federator"));
    }

    // --- createdAt / updatedAt ---

    @Test
    void syncKeyStores_vault_firstWriteSetsCreatedAtAndUpdatedAt() {
        certificateProperties.getDestination().setFile(null);
        certificateProperties.getDestination().setVault(vaultLocation());
        stubCertificateMaterial(certPem, privateKeyPem);
        when(vaultSecretProvider.getSecretAtPath(VAULT_PATH)).thenReturn(Map.of());

        serviceWithRealStores().syncKeyStores();

        Map<String, String> secret = capturePersistedVaultSecret();
        assertEquals("2026-10-22T09:30:00Z", secret.get("createdAt"));
        assertEquals("2026-10-22T09:30:00Z", secret.get("updatedAt"));
    }

    @Test
    void syncKeyStores_vault_updateKeepsCreatedAtAndRefreshesUpdatedAt() {
        certificateProperties.getDestination().setFile(null);
        certificateProperties.getDestination().setVault(vaultLocation());
        stubCertificateMaterial(certPem, privateKeyPem);
        Map<String, Object> existing = inSyncVaultSecret();
        existing.put("truststore.password", "stale");
        when(vaultSecretProvider.getSecretAtPath(VAULT_PATH)).thenReturn(existing);

        serviceWithRealStores(Instant.parse("2026-10-22T11:15:42.987Z")).syncKeyStores();

        Map<String, String> secret = capturePersistedVaultSecret();
        assertEquals("2026-10-01T08:00:00Z", secret.get("createdAt"));
        assertEquals("2026-10-22T11:15:42Z", secret.get("updatedAt"));
    }

    @Test
    void syncKeyStores_vault_inSyncDoesNotTouchTimestamps() {
        certificateProperties.getDestination().setFile(null);
        certificateProperties.getDestination().setVault(vaultLocation());
        stubCertificateMaterial(certPem, privateKeyPem);
        Map<String, Object> existing = inSyncVaultSecret();
        when(vaultSecretProvider.getSecretAtPath(VAULT_PATH)).thenReturn(existing);

        serviceWithRealStores().syncKeyStores();

        verify(vaultSecretProvider, never()).persistSecretAtPath(anyString(), any());
    }

    @Test
    void syncKeyStores_vault_backfillsMissingTimestampsOnInSyncSecret() {
        certificateProperties.getDestination().setFile(null);
        certificateProperties.getDestination().setVault(vaultLocation());
        stubCertificateMaterial(certPem, privateKeyPem);
        Map<String, Object> existing = inSyncVaultSecret();
        existing.remove("createdAt");
        existing.remove("updatedAt");
        when(vaultSecretProvider.getSecretAtPath(VAULT_PATH)).thenReturn(existing);

        serviceWithRealStores().syncKeyStores();

        Map<String, String> secret = capturePersistedVaultSecret();
        assertEquals("2026-10-22T09:30:00Z", secret.get("createdAt"));
        assertEquals("2026-10-22T09:30:00Z", secret.get("updatedAt"));
        assertEquals(existing.get("keystore.p12"), secret.get("keystore.p12"));
    }
}
