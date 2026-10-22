/*
 * SPDX-License-Identifier: Apache-2.0
 * © Crown Copyright 2026. This work has been developed by the National Digital Twin Programme and is legally
 * attributed to the UK's Department for Business, Innovation, Science and Trade (BIST) as the governing entity.
 */

package uk.gov.dbt.ndtp.federator.certificate.manager.client;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import java.io.FileOutputStream;
import java.nio.file.Path;
import java.security.KeyStore;
import java.util.Map;
import org.apache.hc.client5.http.impl.classic.CloseableHttpClient;
import org.apache.hc.client5.http.impl.io.BasicHttpClientConnectionManager;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.test.util.ReflectionTestUtils;
import uk.gov.dbt.ndtp.federator.certificate.manager.config.CertificateProperties;
import uk.gov.dbt.ndtp.federator.certificate.manager.config.CertificateProperties.Destination;
import uk.gov.dbt.ndtp.federator.certificate.manager.config.CertificateProperties.StoreLocation;
import uk.gov.dbt.ndtp.federator.certificate.manager.exception.RestClientConfigurationException;
import uk.gov.dbt.ndtp.federator.certificate.manager.service.pki.VaultSecretProvider;

@ExtendWith(MockitoExtension.class)
class MtlsHttpClientBuilderTest {

    @InjectMocks
    MtlsHttpClientBuilder builder;

    @Mock
    VaultSecretProvider vaultSecretProvider;

    @Mock
    CertificateProperties certificateProperties;

    @TempDir
    Path tempDir;

    private static final String PASSWORD = "password";
    private static final String WRONG_PASSWORD = "wrong-password";
    private static final String TYPE = "PKCS12";
    private static final String KEYSTORE_FILE = "keystore.p12";
    private static final String TRUSTSTORE_FILE = "truststore.p12";

    @BeforeEach
    void setUp() throws Exception {
        Path keyStoreFile = createKeyStore(tempDir.resolve(KEYSTORE_FILE));
        Path trustStoreFile = createKeyStore(tempDir.resolve(TRUSTSTORE_FILE));
        ReflectionTestUtils.setField(builder, "keyStorePath", keyStoreFile.toString());
        ReflectionTestUtils.setField(builder, "trustStorePath", trustStoreFile.toString());
        ReflectionTestUtils.setField(builder, "keyStorePassword", PASSWORD);
        ReflectionTestUtils.setField(builder, "trustStorePassword", PASSWORD);
        ReflectionTestUtils.setField(builder, "keyStoreType", TYPE);
    }

    @Test
    void buildConnectionManager_syncedStore_usesDestinationPassword() {
        setClientPasswords(WRONG_PASSWORD);
        Destination destination = destination(tempDir);
        destination.setKeystorePassword(PASSWORD);
        destination.setTruststorePassword(PASSWORD);
        when(certificateProperties.getDestination()).thenReturn(destination);

        BasicHttpClientConnectionManager connectionManager = builder.buildConnectionManager();

        assertNotNull(connectionManager);
        verifyNoInteractions(vaultSecretProvider);
    }

    @Test
    void buildConnectionManager_syncedStore_usesVaultPassword() {
        setClientPasswords(WRONG_PASSWORD);
        Map<String, Object> secret = Map.of(PASSWORD, PASSWORD);
        when(vaultSecretProvider.getSecret("keystore-password")).thenReturn(secret);
        when(vaultSecretProvider.getSecret("truststore-password")).thenReturn(secret);
        when(certificateProperties.getDestination()).thenReturn(destination(tempDir));

        BasicHttpClientConnectionManager connectionManager = builder.buildConnectionManager();

        assertNotNull(connectionManager);
        verify(vaultSecretProvider, times(2)).getSecret(any());
    }

    @Test
    void buildConnectionManager_syncedStore_fallsBackToClientPasswordWhenVaultHasNone() {
        when(vaultSecretProvider.getSecret(any())).thenReturn(Map.of());
        when(certificateProperties.getDestination()).thenReturn(destination(tempDir));

        BasicHttpClientConnectionManager connectionManager = builder.buildConnectionManager();

        assertNotNull(connectionManager);
        verify(vaultSecretProvider, times(2)).getSecret(any());
    }

    @Test
    void buildConnectionManager_separateStore_ignoresDestinationAndVaultPasswords() {
        // e.g. a bootstrap keystore that is not the file written by the sync job
        Destination destination = destination(tempDir.resolve("synced-output"));
        destination.setKeystorePassword(WRONG_PASSWORD);
        destination.setTruststorePassword(WRONG_PASSWORD);
        when(certificateProperties.getDestination()).thenReturn(destination);

        BasicHttpClientConnectionManager connectionManager = builder.buildConnectionManager();

        assertNotNull(connectionManager);
        verifyNoInteractions(vaultSecretProvider);
    }

    @Test
    void buildConnectionManager_withoutFileDestination_usesClientPassword() {
        when(certificateProperties.getDestination()).thenReturn(new Destination());

        BasicHttpClientConnectionManager connectionManager = builder.buildConnectionManager();

        assertNotNull(connectionManager);
        verifyNoInteractions(vaultSecretProvider);
    }

    @Test
    void buildConnectionManager_wrongPassword_throws() {
        setClientPasswords(WRONG_PASSWORD);
        when(certificateProperties.getDestination()).thenReturn(new Destination());

        assertThrows(RestClientConfigurationException.class, () -> builder.buildConnectionManager());
    }

    @Test
    void buildConnectionManager_WithPassword() {
        BasicHttpClientConnectionManager connectionManager = builder.buildConnectionManager(PASSWORD, PASSWORD);

        assertNotNull(connectionManager);
    }

    @Test
    void buildHttpClient() {
        when(certificateProperties.getDestination()).thenReturn(new Destination());

        CloseableHttpClient httpClient = builder.buildHttpClient();

        assertNotNull(httpClient);
    }

    private void setClientPasswords(String password) {
        ReflectionTestUtils.setField(builder, "keyStorePassword", password);
        ReflectionTestUtils.setField(builder, "trustStorePassword", password);
    }

    private static Destination destination(Path path) {
        StoreLocation file = new StoreLocation();
        file.setPath(path.toString());
        file.setKeystoreFile(KEYSTORE_FILE);
        file.setTruststoreFile(TRUSTSTORE_FILE);
        Destination destination = new Destination();
        destination.setFile(file);
        return destination;
    }

    private static Path createKeyStore(Path file) throws Exception {
        KeyStore ks = KeyStore.getInstance(TYPE);
        ks.load(null, PASSWORD.toCharArray());

        try (FileOutputStream fos = new FileOutputStream(file.toFile())) {
            ks.store(fos, PASSWORD.toCharArray());
        }

        return file;
    }
}
