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

import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.Map;
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

    @BeforeEach
    void setUp() throws Exception {
        realFileSystemService = new FileSystemServiceImpl();
        certificateProperties = new CertificateProperties();
        CertificateProperties.Destination dest = certificateProperties.getDestination();
        dest.setPath(tempDir.toString());
        dest.setKeystoreFile("keystore.p12");
        dest.setTruststoreFile("truststore.p12");
        dest.setKeystoreAlias("federator");
        dest.setKeystorePassword("ks-pass");
        dest.setTruststorePassword("ts-pass");
        dest.setKeystorePasswordFile("keystore.password");
        dest.setTruststorePasswordFile("truststore.password");

        keyStoreSyncService = new KeyStoreSyncServiceImpl(
                certificateProperties, vaultSecretProvider, keyStoreService, realFileSystemService);

        // Generate test certs and real keystore bytes
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        KeyPair caKeyPair = kpg.generateKeyPair();
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

    // --- syncKeyStoresToFilesystem ---

    @Test
    void syncKeyStoresToFilesystem_createsKeystoreAndTruststore() {
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

        keyStoreSyncService.syncKeyStoresToFilesystem();

        assertTrue(Files.exists(tempDir.resolve("keystore.p12")));
        assertTrue(Files.exists(tempDir.resolve("truststore.p12")));
        assertTrue(Files.exists(tempDir.resolve("keystore.password")));
        assertTrue(Files.exists(tempDir.resolve("truststore.password")));
    }

    @Test
    void syncKeyStoresToFilesystem_skipsUpdateWhenInSync() throws Exception {
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

        keyStoreSyncService.syncKeyStoresToFilesystem();

        verify(keyStoreService, never()).createKeyStore(any(), any(), any(), any(), any());
        verify(keyStoreService, never()).createTrustStore(any(), any(), any());
    }

    @Test
    void syncKeyStoresToFilesystem_skipsWhenNoCertificate() {
        when(vaultSecretProvider.getCertificate()).thenReturn(null);
        when(vaultSecretProvider.getKeyPair()).thenReturn(null);
        when(vaultSecretProvider.getCaChain()).thenReturn(List.of());

        keyStoreSyncService.syncKeyStoresToFilesystem();

        verify(keyStoreService, never()).createKeyStore(any(), any(), any(), any(), any());
        verify(keyStoreService, never()).createTrustStore(any(), any(), any());
    }

    @Test
    void syncKeyStoresToFilesystem_fallsBackToIntermediateCaWhenCaChainEmpty() {
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

        keyStoreSyncService.syncKeyStoresToFilesystem();

        verify(keyStoreService).createTrustStore(eq(List.of(caPem)), anyString(), any());
    }

    @Test
    void syncKeyStoresToFilesystem_fallsBackToIntermediateCaWhenCaChainNull() {
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

        keyStoreSyncService.syncKeyStoresToFilesystem();

        verify(keyStoreService).createTrustStore(eq(List.of(caPem)), anyString(), any());
    }

    @Test
    void syncKeyStoresToFilesystem_skipsTruststoreWhenNoCaChainAndNoIntermediateCa() {
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

        keyStoreSyncService.syncKeyStoresToFilesystem();

        verify(keyStoreService, never()).createTrustStore(any(), any(), any());
    }

    @Test
    void syncKeyStoresToFilesystem_handlesCorruptExistingKeystore() throws Exception {
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

        keyStoreSyncService.syncKeyStoresToFilesystem();

        verify(keyStoreService).createKeyStore(anyString(), anyString(), any(), anyString(), anyString());
    }

    @Test
    void syncKeyStoresToFilesystem_handlesCorruptExistingTruststore() throws Exception {
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

        keyStoreSyncService.syncKeyStoresToFilesystem();

        verify(keyStoreService).createTrustStore(any(), anyString(), any());
    }

    @Test
    void syncKeyStoresToFilesystem_skipsWhenNoPrivateKey() {
        CreateKeyResponseDTO keyPair =
                CreateKeyResponseDTO.builder().publicKeyPem("pub").build();

        when(vaultSecretProvider.getCertificate()).thenReturn(certPem);
        when(vaultSecretProvider.getKeyPair()).thenReturn(keyPair);
        when(vaultSecretProvider.getCaChain()).thenReturn(List.of(caPem));
        when(keyStoreService.createTrustStore(any(), anyString(), any())).thenReturn(validTruststoreBytes);

        keyStoreSyncService.syncKeyStoresToFilesystem();

        verify(keyStoreService, never()).createKeyStore(any(), any(), any(), any(), any());
        verify(keyStoreService).createTrustStore(any(), anyString(), any());
    }

    @Test
    void syncKeyStoresToFilesystem_updatesWhenCaChainDiffers() throws Exception {
        Files.write(tempDir.resolve("truststore.p12"), validTruststoreBytes);
        Files.write(tempDir.resolve("truststore.password"), "ts-pass".getBytes());

        when(vaultSecretProvider.getCertificate()).thenReturn(null);
        when(vaultSecretProvider.getKeyPair()).thenReturn(null);
        when(vaultSecretProvider.getCaChain()).thenReturn(List.of(caPem, caPem));
        Path trustStorePath = tempDir.resolve("truststore.p12");
        byte[] newTruststoreBytes =
                realKeyStoreService.createTrustStore(List.of(caPem, caPem), "ts-pass", trustStorePath);
        when(keyStoreService.createTrustStore(any(), anyString(), any())).thenReturn(newTruststoreBytes);

        keyStoreSyncService.syncKeyStoresToFilesystem();

        verify(keyStoreService).createTrustStore(any(), anyString(), any());
    }

    @Test
    void syncKeyStoresToFilesystem_passwordFileAlreadyInSync() throws Exception {
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

        keyStoreSyncService.syncKeyStoresToFilesystem();

        assertTrue(Files.exists(tempDir.resolve("keystore.password")));
        assertTrue(Files.exists(tempDir.resolve("truststore.password")));
    }

    @Test
    void syncKeyStoresToFilesystem_handlesEmptyCaChainInKeystore() {
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

        keyStoreSyncService.syncKeyStoresToFilesystem();

        verify(keyStoreService).createKeyStore(anyString(), anyString(), any(), anyString(), anyString());
    }

    // --- validateKeyStore: KeyStoreCreationException ---

    @Test
    void syncKeyStoresToFilesystem_throwsKeyStoreCreationExceptionForInvalidKeystoreBytes() {
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
            keyStoreSyncService.syncKeyStoresToFilesystem();
        });

        assertEquals("Failed to validate generated keystore", ex.getMessage());
        assertNotNull(ex.getCause());
    }

    @Test
    void syncKeyStoresToFilesystem_throwsKeyStoreCreationExceptionWhenAliasMissing() {
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
            keyStoreSyncService.syncKeyStoresToFilesystem();
        });

        assertTrue(ex.getMessage().contains("Generated keystore missing expected alias: federator"));
        assertNull(ex.getCause());
    }

    // --- validateTrustStore: KeyStoreCreationException ---

    @Test
    void syncKeyStoresToFilesystem_throwsKeyStoreCreationExceptionForInvalidTruststoreBytes() {
        when(vaultSecretProvider.getCertificate()).thenReturn(null);
        when(vaultSecretProvider.getKeyPair()).thenReturn(null);
        when(vaultSecretProvider.getCaChain()).thenReturn(List.of(caPem));
        when(keyStoreService.createTrustStore(any(), anyString(), any())).thenReturn(new byte[] {0x00, 0x01, 0x02});

        KeyStoreCreationException ex = assertThrows(KeyStoreCreationException.class, () -> {
            keyStoreSyncService.syncKeyStoresToFilesystem();
        });

        assertEquals("Failed to validate generated truststore", ex.getMessage());
        assertNotNull(ex.getCause());
    }

    // --- writePasswordToFile: FileSystemException ---

    @Test
    void syncKeyStoresToFilesystem_propagatesFileSystemExceptionFromPasswordWrite() {
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

        FileSystemException ex = assertThrows(FileSystemException.class, serviceWithMockFs::syncKeyStoresToFilesystem);

        assertEquals("disk full", ex.getMessage());
    }

    // --- shouldUpdateKeyStore edge cases ---

    @Test
    void syncKeyStoresToFilesystem_updatesWhenExistingKeystoreHasDifferentKey() throws Exception {
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

        keyStoreSyncService.syncKeyStoresToFilesystem();

        verify(keyStoreService).createKeyStore(anyString(), anyString(), any(), anyString(), anyString());
    }

    @Test
    void syncKeyStoresToFilesystem_updatesWhenExistingKeystoreHasDifferentChainLength() throws Exception {
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

        keyStoreSyncService.syncKeyStoresToFilesystem();

        verify(keyStoreService).createKeyStore(anyString(), anyString(), any(), anyString(), anyString());
    }

    // --- shouldUpdateTrustStore edge cases ---

    @Test
    void syncKeyStoresToFilesystem_updatesWhenTruststoreHasDifferentCert() throws Exception {
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

        keyStoreSyncService.syncKeyStoresToFilesystem();

        verify(keyStoreService).createTrustStore(any(), anyString(), any());
    }

    @Test
    void syncKeyStoresToFilesystem_updatesWhenTruststoreMissingAlias() throws Exception {
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

        keyStoreSyncService.syncKeyStoresToFilesystem();

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
    void syncKeyStoresToFilesystem_writesPasswordWhenStorePathHasNoParent() {
        // Use a destination with a relative file name that has no parent
        CertificateProperties.Destination dest = certificateProperties.getDestination();
        dest.setPath(tempDir.toString());

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

        assertDoesNotThrow(() -> keyStoreSyncService.syncKeyStoresToFilesystem());
    }

    // --- password resolution during sync (no configured password) ---

    @Test
    void syncKeyStoresToFilesystem_resolvesPasswordFromVaultWhenNotConfigured() {
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

        keyStoreSyncService.syncKeyStoresToFilesystem();

        assertTrue(Files.exists(tempDir.resolve("keystore.p12")));
        assertTrue(Files.exists(tempDir.resolve("truststore.p12")));
    }

    @Test
    void syncKeyStoresToFilesystem_generatesAndPersistsPasswordWhenNotInVault() {
        CertificateProperties.Destination dest = certificateProperties.getDestination();
        dest.setKeystorePassword(null);
        dest.setTruststorePassword(null);

        when(vaultSecretProvider.getSecret("keystore-password")).thenReturn(Collections.emptyMap());
        when(vaultSecretProvider.getSecret("truststore-password")).thenReturn(Collections.emptyMap());

        when(vaultSecretProvider.getCertificate()).thenReturn(null);
        when(vaultSecretProvider.getKeyPair()).thenReturn(null);
        when(vaultSecretProvider.getCaChain()).thenReturn(List.of());
        when(vaultSecretProvider.getIntermediateCa()).thenReturn(null);

        keyStoreSyncService.syncKeyStoresToFilesystem();

        verify(vaultSecretProvider).persistSecret(eq("keystore-password"), any());
        verify(vaultSecretProvider).persistSecret(eq("truststore-password"), any());
    }
}
