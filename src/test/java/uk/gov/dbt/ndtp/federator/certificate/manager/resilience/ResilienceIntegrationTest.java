/*
 * SPDX-License-Identifier: Apache-2.0
 * © Crown Copyright 2026. This work has been developed by the National Digital Twin Programme and is legally
 * attributed to the UK's Department for Business, Innovation, Science and Trade (BIST) as the governing entity.
 */

package uk.gov.dbt.ndtp.federator.certificate.manager.resilience;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.reset;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import io.github.resilience4j.circuitbreaker.CallNotPermittedException;
import io.github.resilience4j.circuitbreaker.CircuitBreaker;
import io.github.resilience4j.circuitbreaker.CircuitBreakerRegistry;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.vault.core.VaultSysOperations;
import org.springframework.vault.core.VaultTemplate;
import org.springframework.vault.core.VaultVersionedKeyValueOperations;
import org.springframework.vault.support.VaultMount;
import uk.gov.dbt.ndtp.federator.certificate.manager.client.MtlsHttpClientBuilder;
import uk.gov.dbt.ndtp.federator.certificate.manager.exception.ManagementNodeException;
import uk.gov.dbt.ndtp.federator.certificate.manager.exception.OAuth2TokenException;
import uk.gov.dbt.ndtp.federator.certificate.manager.exception.VaultException;
import uk.gov.dbt.ndtp.federator.certificate.manager.service.ManagementNodeService;
import uk.gov.dbt.ndtp.federator.certificate.manager.service.idp.OAuth2TokenService;
import uk.gov.dbt.ndtp.federator.certificate.manager.service.idp.TokenCacheService;
import uk.gov.dbt.ndtp.federator.certificate.manager.service.pki.VaultSecretProvider;

@SpringBootTest
@ActiveProfiles("resilience-test")
class ResilienceIntegrationTest {

    @Autowired
    private ManagementNodeService managementNodeService;

    @Autowired
    private OAuth2TokenService oAuth2TokenService;

    @Autowired
    private VaultSecretProvider vaultSecretProvider;

    @Autowired
    private CircuitBreakerRegistry circuitBreakerRegistry;

    @MockitoBean
    private MtlsHttpClientBuilder httpClientBuilder;

    @MockitoBean
    private TokenCacheService tokenCacheService;

    @MockitoBean
    private VaultTemplate vaultTemplate;

    @BeforeEach
    void setUp() {
        circuitBreakerRegistry.getAllCircuitBreakers().forEach(CircuitBreaker::reset);
        reset(httpClientBuilder, tokenCacheService);
        when(tokenCacheService.getToken()).thenReturn("test-token");
    }

    @Test
    void managementNode_retriesOnFailure() {
        when(httpClientBuilder.buildHttpClient()).thenThrow(new RuntimeException("Connection refused"));

        assertThrows(ManagementNodeException.class, () -> managementNodeService.getIntermediateCertificate());

        verify(httpClientBuilder, times(3)).buildHttpClient();
    }

    @Test
    void managementNode_circuitBreakerOpensAfterFailures() {
        when(httpClientBuilder.buildHttpClient()).thenThrow(new RuntimeException("Connection refused"));

        for (int i = 0; i < 10; i++) {
            try {
                managementNodeService.getIntermediateCertificate();
            } catch (Exception ignored) {
                // Failures are expected here to trip the circuit breaker
            }
        }

        reset(httpClientBuilder);
        assertThrows(CallNotPermittedException.class, () -> managementNodeService.getIntermediateCertificate());
        verify(httpClientBuilder, times(0)).buildHttpClient();
    }

    @Test
    void oauth2_retriesOnFailure() {
        when(httpClientBuilder.buildHttpClient()).thenThrow(new RuntimeException("Connection refused"));

        assertThrows(OAuth2TokenException.class, () -> oAuth2TokenService.getAccessToken());

        verify(httpClientBuilder, times(3)).buildHttpClient();
    }

    @Test
    void oauth2_circuitBreakerOpensAfterFailures() {
        when(httpClientBuilder.buildHttpClient()).thenThrow(new RuntimeException("Connection refused"));

        for (int i = 0; i < 10; i++) {
            try {
                oAuth2TokenService.getAccessToken();
            } catch (Exception ignored) {
                // Failures are expected here to trip the circuit breaker
            }
        }

        reset(httpClientBuilder);
        assertThrows(CallNotPermittedException.class, () -> oAuth2TokenService.getAccessToken());
        verify(httpClientBuilder, times(0)).buildHttpClient();
    }

    @Test
    void vault_retriesOnFailure() {
        stubVaultMountCheck();
        VaultVersionedKeyValueOperations kvOps = Mockito.mock(VaultVersionedKeyValueOperations.class);
        when(vaultTemplate.opsForVersionedKeyValue("node-net")).thenReturn(kvOps);
        when(kvOps.get("client/certificate")).thenThrow(new RuntimeException("Vault unavailable"));

        assertThrows(VaultException.class, () -> vaultSecretProvider.getCertificate());

        verify(kvOps, times(3)).get("client/certificate");
    }

    @Test
    void vault_circuitBreakerOpensAfterFailures() {
        stubVaultMountCheck();
        VaultVersionedKeyValueOperations kvOps = Mockito.mock(VaultVersionedKeyValueOperations.class);
        when(vaultTemplate.opsForVersionedKeyValue("node-net")).thenReturn(kvOps);
        when(kvOps.get("client/certificate")).thenThrow(new RuntimeException("Vault unavailable"));

        for (int i = 0; i < 10; i++) {
            try {
                vaultSecretProvider.getCertificate();
            } catch (Exception ignored) {
                // Failures are expected here to trip the circuit breaker
            }
        }

        reset(vaultTemplate);
        assertThrows(CallNotPermittedException.class, () -> vaultSecretProvider.getCertificate());
    }

    private void stubVaultMountCheck() {
        VaultSysOperations sysOps = Mockito.mock(VaultSysOperations.class);
        when(vaultTemplate.opsForSys()).thenReturn(sysOps);
        when(sysOps.getMounts())
                .thenReturn(Map.of("node-net/", VaultMount.builder().type("kv").build()));
    }
}
