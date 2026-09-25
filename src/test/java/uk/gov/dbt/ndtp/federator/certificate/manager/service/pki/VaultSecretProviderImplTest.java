/*
 * SPDX-License-Identifier: Apache-2.0
 * © Crown Copyright 2026. This work has been developed by the National Digital Twin Programme and is legally
 * attributed to the UK's Department for Business, Innovation, Science and Trade (BIST) as the governing entity.
 */

package uk.gov.dbt.ndtp.federator.certificate.manager.service.pki;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyMap;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.util.Collections;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;
import org.springframework.vault.core.VaultSysOperations;
import org.springframework.vault.core.VaultTemplate;
import org.springframework.vault.core.VaultVersionedKeyValueOperations;
import org.springframework.vault.support.VaultMount;
import org.springframework.vault.support.Versioned;
import uk.gov.dbt.ndtp.federator.certificate.manager.exception.VaultException;
import uk.gov.dbt.ndtp.federator.certificate.manager.model.dto.CreateKeyResponseDTO;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class VaultSecretProviderImplTest {

    @Mock
    private VaultTemplate vaultTemplate;

    @Mock
    private VaultSysOperations sysOps;

    @Mock
    private VaultVersionedKeyValueOperations kvOps;

    private VaultSecretProviderImpl vaultSecretProvider;

    private static final String BASE_PATH = "node-net/client";

    @BeforeEach
    void setUp() {
        vaultSecretProvider = new VaultSecretProviderImpl(vaultTemplate, BASE_PATH);
        when(vaultTemplate.opsForSys()).thenReturn(sysOps);
        // Default: mount exists
        when(sysOps.getMounts())
                .thenReturn(Map.of("node-net/", VaultMount.builder().type("kv").build()));
        when(vaultTemplate.opsForVersionedKeyValue("node-net")).thenReturn(kvOps);
    }

    @Test
    void persistKeyPair_success() {
        CreateKeyResponseDTO dto = CreateKeyResponseDTO.builder()
                .publicKeyPem("public")
                .privateKeyPem("private")
                .build();

        vaultSecretProvider.persistKeyPair(dto);

        verify(sysOps, times(1)).getMounts();
        verify(sysOps, times(0)).mount(any(), any());
        verify(kvOps, times(1)).put(eq("client/keypair"), anyMap());
    }

    @Test
    void persistKeyPair_mountAlreadyExists() {
        when(sysOps.getMounts())
                .thenReturn(Map.of("node-net/", VaultMount.builder().type("kv").build()));

        CreateKeyResponseDTO dto = CreateKeyResponseDTO.builder()
                .publicKeyPem("public")
                .privateKeyPem("private")
                .build();

        vaultSecretProvider.persistKeyPair(dto);

        verify(sysOps, times(0)).mount(eq("node-net"), any(VaultMount.class));
        verify(kvOps, times(1)).put(eq("client/keypair"), anyMap());
    }

    @Test
    void constructor_edgeCases() {
        VaultSecretProviderImpl provider1 = new VaultSecretProviderImpl(vaultTemplate, "simplemount");

        when(sysOps.getMounts())
                .thenReturn(
                        Map.of("simplemount/", VaultMount.builder().type("kv").build()));

        CreateKeyResponseDTO dto = CreateKeyResponseDTO.builder()
                .publicKeyPem("public")
                .privateKeyPem("private")
                .build();

        when(vaultTemplate.opsForVersionedKeyValue("simplemount")).thenReturn(kvOps);
        provider1.persistKeyPair(dto);
        verify(kvOps, times(1)).put(eq("keypair"), anyMap());
    }

    @Test
    void persistKeyPair_failure() {
        CreateKeyResponseDTO dto = CreateKeyResponseDTO.builder()
                .publicKeyPem("public")
                .privateKeyPem("private")
                .build();

        doThrow(new RuntimeException("Vault down")).when(kvOps).put(eq("client/keypair"), anyMap());

        assertThrows(VaultException.class, () -> vaultSecretProvider.persistKeyPair(dto));

        verify(sysOps, times(1)).getMounts();
        verify(kvOps, times(1)).put(eq("client/keypair"), anyMap());
    }

    @Test
    void ensureKvMountExists_failure() {
        when(vaultTemplate.opsForSys()).thenThrow(new RuntimeException("sys unavailable"));

        CreateKeyResponseDTO dto = CreateKeyResponseDTO.builder()
                .publicKeyPem("public")
                .privateKeyPem("private")
                .build();

        assertThrows(VaultException.class, () -> vaultSecretProvider.persistKeyPair(dto));
        verify(kvOps, times(0)).put(any(), anyMap());
    }

    @Test
    void ensureKvMountExists_throwsWhenMountNotFound() {
        when(sysOps.getMounts()).thenReturn(Collections.emptyMap());

        VaultSecretProviderImpl provider = new VaultSecretProviderImpl(vaultTemplate, BASE_PATH);
        assertThrows(VaultException.class, provider::ensureKvMountExists);
    }

    @Test
    void persistCertificate_success() {
        vaultSecretProvider.persistCertificate("-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----\n");
        verify(sysOps, times(1)).getMounts();
        verify(kvOps, times(1)).put(eq("client/certificate"), anyMap());
    }

    @Test
    void persistCertificate_failure() {
        doThrow(new RuntimeException("Vault down")).when(kvOps).put(eq("client/certificate"), anyMap());

        assertThrows(VaultException.class, () -> vaultSecretProvider.persistCertificate("cert-pem"));
    }

    @Test
    void persistCaChain_success() {
        List<String> chain = List.of("cert1", "cert2");
        vaultSecretProvider.persistCaChain(chain);
        verify(sysOps, times(1)).getMounts();
        verify(kvOps, times(1)).put(eq("client/ca-chain"), anyMap());
    }

    @Test
    void persistCaChain_failure() {
        doThrow(new RuntimeException("Vault down")).when(kvOps).put(eq("client/ca-chain"), anyMap());

        List<String> caChain = List.of("cert");

        assertThrows(VaultException.class, () -> vaultSecretProvider.persistCaChain(caChain));
    }

    @Test
    void persistIntermediateCa_success() {
        vaultSecretProvider.persistIntermediateCa("-----BEGIN CERTIFICATE-----\nINT\n-----END CERTIFICATE-----\n");
        verify(sysOps, times(1)).getMounts();
        verify(kvOps, times(1)).put(eq("client/intermediate-ca"), anyMap());
    }

    @Test
    void persistIntermediateCa_failure() {
        doThrow(new RuntimeException("Vault down")).when(kvOps).put(eq("client/intermediate-ca"), anyMap());

        assertThrows(VaultException.class, () -> vaultSecretProvider.persistIntermediateCa("cert"));
    }

    @Test
    void getCertificate_success() {
        Versioned<Map<String, Object>> versioned = mock(Versioned.class);
        when(versioned.getData()).thenReturn(Map.of("certificate", "cert-content"));
        when(kvOps.get("client/certificate")).thenReturn(versioned);

        String result = vaultSecretProvider.getCertificate();

        assertEquals("cert-content", result);
    }

    @Test
    void getCertificate_notFound() {
        when(kvOps.get("client/certificate")).thenReturn(null);

        String result = vaultSecretProvider.getCertificate();

        assertNull(result);
    }

    @Test
    void getCertificate_failure() {
        when(kvOps.get("client/certificate")).thenThrow(new RuntimeException("read failed"));

        assertThrows(VaultException.class, () -> vaultSecretProvider.getCertificate());
    }

    @Test
    void getIntermediateCa_success() {
        Versioned<Map<String, Object>> versioned = mock(Versioned.class);
        when(versioned.getData()).thenReturn(Map.of("certificate", "cert-content"));
        when(kvOps.get("client/intermediate-ca")).thenReturn(versioned);

        String result = vaultSecretProvider.getIntermediateCa();

        assertEquals("cert-content", result);
        verify(kvOps).get("client/intermediate-ca");
    }

    @Test
    void getIntermediateCa_notFound() {
        when(kvOps.get("client/intermediate-ca")).thenReturn(null);

        String result = vaultSecretProvider.getIntermediateCa();

        assertNull(result);
    }

    @Test
    void getIntermediateCa_failure() {
        when(kvOps.get("client/intermediate-ca")).thenThrow(new RuntimeException("read failed"));

        assertThrows(VaultException.class, () -> vaultSecretProvider.getIntermediateCa());
    }

    @Test
    void persistSecret_success() {
        Map<String, String> data = Map.of("password", "secret123");
        vaultSecretProvider.persistSecret("test-secret", data);
        verify(kvOps).put(("client/test-secret"), (data));
    }

    @Test
    void getSecret_success() {
        Versioned<Map<String, Object>> versioned = mock(Versioned.class);
        Map<String, Object> data = Map.of("password", "secret123");
        when(versioned.getData()).thenReturn(data);
        when(kvOps.get("client/test-secret")).thenReturn(versioned);

        Map<String, Object> result = vaultSecretProvider.getSecret("test-secret");

        assertEquals(data, result);
        verify(kvOps).get("client/test-secret");
    }

    @Test
    void getSecret_notFound() {
        when(kvOps.get("client/test-secret")).thenReturn(null);
        Map<String, Object> result = vaultSecretProvider.getSecret("test-secret");
        assertNotNull(result);
        assertTrue(result.isEmpty());
    }

    @Test
    void getSecret_failure() {
        when(kvOps.get("client/test-secret")).thenThrow(new RuntimeException("read failed"));

        assertThrows(VaultException.class, () -> vaultSecretProvider.getSecret("test-secret"));
    }

    @Test
    void getKeyPair_success() {
        Versioned<Map<String, Object>> versioned = mock(Versioned.class);
        when(versioned.getData())
                .thenReturn(Map.of(
                        "publicKey", "pub-pem",
                        "privateKey", "priv-pem"));
        when(kvOps.get("client/keypair")).thenReturn(versioned);

        CreateKeyResponseDTO result = vaultSecretProvider.getKeyPair();

        assertNotNull(result);
        assertEquals("pub-pem", result.getPublicKeyPem());
        assertEquals("priv-pem", result.getPrivateKeyPem());
    }

    @Test
    void getKeyPair_notFound() {
        when(kvOps.get("client/keypair")).thenReturn(null);

        CreateKeyResponseDTO result = vaultSecretProvider.getKeyPair();

        assertNull(result);
    }

    @Test
    void getKeyPair_failure() {
        when(kvOps.get("client/keypair")).thenThrow(new RuntimeException("read failed"));

        assertThrows(VaultException.class, () -> vaultSecretProvider.getKeyPair());
    }

    @Test
    void getCaChain_success() {
        Versioned<Map<String, Object>> versioned = mock(Versioned.class);
        String chain =
                """
                -----BEGIN CERTIFICATE-----
                C1
                -----END CERTIFICATE-----
                -----BEGIN CERTIFICATE-----
                C2
                -----END CERTIFICATE-----""";
        when(versioned.getData()).thenReturn(Map.of("chain", chain));
        when(kvOps.get("client/ca-chain")).thenReturn(versioned);

        List<String> result = vaultSecretProvider.getCaChain();

        assertEquals(2, result.size());
        assertEquals("-----BEGIN CERTIFICATE-----\nC1\n-----END CERTIFICATE-----\n", result.get(0));
        assertEquals("-----BEGIN CERTIFICATE-----\nC2\n-----END CERTIFICATE-----\n", result.get(1));
    }

    @Test
    void getCaChain_notFound() {
        when(kvOps.get("client/ca-chain")).thenReturn(null);

        List<String> result = vaultSecretProvider.getCaChain();

        assertNotNull(result);
        assertTrue(result.isEmpty());
    }

    @Test
    void getCaChain_failure() {
        when(kvOps.get("client/ca-chain")).thenThrow(new RuntimeException("read failed"));

        assertThrows(VaultException.class, () -> vaultSecretProvider.getCaChain());
    }

    @Test
    void ensureKvMountExists_cachesAfterFirstCheck() {
        // First call checks the mount
        vaultSecretProvider.ensureKvMountExists();
        verify(sysOps, times(1)).getMounts();

        // Second call should be cached
        vaultSecretProvider.ensureKvMountExists();
        verify(sysOps, times(1)).getMounts(); // Still 1 call, not 2
    }

    @Test
    void getKeyPair_handlesNonStringValues() {
        Versioned<Map<String, Object>> versioned = mock(Versioned.class);
        when(versioned.getData()).thenReturn(Map.of("publicKey", 123, "privateKey", 456));
        when(kvOps.get("client/keypair")).thenReturn(versioned);

        CreateKeyResponseDTO result = vaultSecretProvider.getKeyPair();

        assertNotNull(result);
        assertNull(result.getPublicKeyPem());
        assertNull(result.getPrivateKeyPem());
    }

    @Test
    void getCertificate_returnsNullForNonStringValue() {
        Versioned<Map<String, Object>> versioned = mock(Versioned.class);
        when(versioned.getData()).thenReturn(Map.of("certificate", 123));
        when(kvOps.get("client/certificate")).thenReturn(versioned);

        String result = vaultSecretProvider.getCertificate();
        assertNull(result);
    }

    @Test
    void getIntermediateCa_returnsNullForNonStringValue() {
        Versioned<Map<String, Object>> versioned = mock(Versioned.class);
        when(versioned.getData()).thenReturn(Map.of("certificate", 123));
        when(kvOps.get("client/intermediate-ca")).thenReturn(versioned);

        String result = vaultSecretProvider.getIntermediateCa();
        assertNull(result);
    }

    @Test
    void getCaChain_emptyChainString() {
        Versioned<Map<String, Object>> versioned = mock(Versioned.class);
        when(versioned.getData()).thenReturn(Map.of("chain", "   "));
        when(kvOps.get("client/ca-chain")).thenReturn(versioned);

        List<String> result = vaultSecretProvider.getCaChain();
        assertTrue(result.isEmpty());
    }

    @Test
    void getCertificate_returnsNullWhenDataIsNull() {
        Versioned<Map<String, Object>> versioned = mock(Versioned.class);
        when(versioned.getData()).thenReturn(null);
        when(kvOps.get("client/certificate")).thenReturn(versioned);

        String result = vaultSecretProvider.getCertificate();
        assertNull(result);
    }

    @Test
    void getKeyPair_returnsNullWhenDataIsNull() {
        Versioned<Map<String, Object>> versioned = mock(Versioned.class);
        when(versioned.getData()).thenReturn(null);
        when(kvOps.get("client/keypair")).thenReturn(versioned);

        CreateKeyResponseDTO result = vaultSecretProvider.getKeyPair();
        assertNull(result);
    }

    @Test
    void getCaChain_returnsEmptyWhenDataIsNull() {
        Versioned<Map<String, Object>> versioned = mock(Versioned.class);
        when(versioned.getData()).thenReturn(null);
        when(kvOps.get("client/ca-chain")).thenReturn(versioned);

        List<String> result = vaultSecretProvider.getCaChain();
        assertNotNull(result);
        assertTrue(result.isEmpty());
    }

    @Test
    void getIntermediateCa_returnsNullWhenDataIsNull() {
        Versioned<Map<String, Object>> versioned = mock(Versioned.class);
        when(versioned.getData()).thenReturn(null);
        when(kvOps.get("client/intermediate-ca")).thenReturn(versioned);

        String result = vaultSecretProvider.getIntermediateCa();
        assertNull(result);
    }

    @Test
    void getSecret_returnsEmptyMapWhenDataIsNull() {
        Versioned<Map<String, Object>> versioned = mock(Versioned.class);
        when(versioned.getData()).thenReturn(null);
        when(kvOps.get("client/test-secret")).thenReturn(versioned);

        Map<String, Object> result = vaultSecretProvider.getSecret("test-secret");
        assertNotNull(result);
        assertTrue(result.isEmpty());
    }
}
