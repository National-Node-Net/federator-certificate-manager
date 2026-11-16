/*
 * SPDX-License-Identifier: Apache-2.0
 * © Crown Copyright 2026. This work has been developed by the National Digital Twin Programme and is legally
 * attributed to the UK's Department for Business, Innovation, Science and Trade (BIST) as the governing entity.
 */

package uk.gov.dbt.ndtp.federator.certificate.manager.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.when;

import org.apache.hc.client5.http.impl.classic.CloseableHttpClient;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpHeaders;
import org.springframework.web.client.RestClient;
import uk.gov.dbt.ndtp.federator.certificate.manager.client.MtlsHttpClientBuilder;
import uk.gov.dbt.ndtp.federator.certificate.manager.exception.ManagementNodeException;
import uk.gov.dbt.ndtp.federator.certificate.manager.model.dto.CertificateResponseDTO;
import uk.gov.dbt.ndtp.federator.certificate.manager.model.dto.SignCertRequestDTO;
import uk.gov.dbt.ndtp.federator.certificate.manager.model.dto.SignCertResponseDTO;
import uk.gov.dbt.ndtp.federator.certificate.manager.service.idp.TokenCacheService;

@ExtendWith(MockitoExtension.class)
class ManagementNodeServiceImplTest {

    @Mock
    private MtlsHttpClientBuilder builder;

    @Mock
    private TokenCacheService tokenCacheService;

    private ManagementNodeServiceImpl managementNodeService;

    private final String baseUrl = "https://localhost:8090";

    @BeforeEach
    void setUp() {
        managementNodeService = new ManagementNodeServiceImpl(tokenCacheService, baseUrl, builder);
    }

    @Test
    void getIntermediateCertificate_returnsResponseOnSuccess() {
        String token = "test-token";
        CertificateResponseDTO expectedResponse =
                CertificateResponseDTO.builder().certificate("cert-data").build();
        when(tokenCacheService.getToken()).thenReturn(token);

        CloseableHttpClient httpClient = mock(CloseableHttpClient.class);
        RestClient restClient = mock(RestClient.class);
        when(builder.buildHttpClient()).thenReturn(httpClient);
        managementNodeService = spy(managementNodeService);
        doReturn(restClient).when(managementNodeService).buildRestClient(httpClient);

        RestClient.RequestHeadersUriSpec requestHeadersUriSpec = mock(RestClient.RequestHeadersUriSpec.class);
        RestClient.RequestHeadersSpec requestHeadersSpec = mock(RestClient.RequestHeadersSpec.class);
        RestClient.ResponseSpec responseSpec = mock(RestClient.ResponseSpec.class);
        when(restClient.get()).thenReturn(requestHeadersUriSpec);

        when(requestHeadersUriSpec.uri(baseUrl + ManagementNodeServiceImpl.INTERMEDIATE_CERT_PATH))
                .thenReturn(requestHeadersSpec);
        when(requestHeadersSpec.header(HttpHeaders.AUTHORIZATION, ManagementNodeServiceImpl.BEARER_PREFIX + token))
                .thenReturn(requestHeadersSpec);
        when(requestHeadersSpec.retrieve()).thenReturn(responseSpec);
        when(responseSpec.body(CertificateResponseDTO.class)).thenReturn(expectedResponse);

        CertificateResponseDTO actualResponse = managementNodeService.getIntermediateCertificate();

        assertEquals(expectedResponse, actualResponse);
    }

    @Test
    void getIntermediateCertificate_throwsExceptionOnFailure() {
        when(tokenCacheService.getToken()).thenReturn("token");

        ManagementNodeException ex =
                assertThrows(ManagementNodeException.class, () -> managementNodeService.getIntermediateCertificate());
        assertEquals("Failed to retrieve intermediate certificate", ex.getMessage());
    }

    @Test
    void getIntermediateCertificate_throwsWhenTokenFails() {
        when(tokenCacheService.getToken()).thenThrow(new RuntimeException("token error"));

        assertThrows(RuntimeException.class, () -> managementNodeService.getIntermediateCertificate());
    }

    @Test
    void signCertificate_returnsResponseOnSuccess() {
        String token = "test-token";
        when(tokenCacheService.getToken()).thenReturn(token);

        SignCertRequestDTO request = SignCertRequestDTO.builder().csr("csr-pem").build();
        SignCertResponseDTO expectedResponse =
                SignCertResponseDTO.builder().certificate("signed-cert").build();

        CloseableHttpClient httpClient = mock(CloseableHttpClient.class);
        RestClient restClient = mock(RestClient.class);
        when(builder.buildHttpClient()).thenReturn(httpClient);
        managementNodeService = spy(managementNodeService);
        doReturn(restClient).when(managementNodeService).buildRestClient(httpClient);

        RestClient.RequestBodyUriSpec requestBodyUriSpec = mock(RestClient.RequestBodyUriSpec.class);
        RestClient.RequestBodySpec requestBodySpec = mock(RestClient.RequestBodySpec.class);
        RestClient.ResponseSpec responseSpec = mock(RestClient.ResponseSpec.class);
        when(restClient.post()).thenReturn(requestBodyUriSpec);

        when(requestBodyUriSpec.uri(baseUrl + ManagementNodeServiceImpl.SIGN_CSR_PATH))
                .thenReturn(requestBodySpec);
        when(requestBodySpec.header(HttpHeaders.AUTHORIZATION, ManagementNodeServiceImpl.BEARER_PREFIX + token))
                .thenReturn(requestBodySpec);
        when(requestBodySpec.body(request)).thenReturn(requestBodySpec);
        when(requestBodySpec.retrieve()).thenReturn(responseSpec);
        when(responseSpec.body(SignCertResponseDTO.class)).thenReturn(expectedResponse);

        SignCertResponseDTO actualResponse = managementNodeService.signCertificate(request);

        assertNotNull(actualResponse);
        assertEquals("signed-cert", actualResponse.getCertificate());
    }

    @Test
    void signCertificate_throwsExceptionOnFailure() {
        when(tokenCacheService.getToken()).thenReturn("token");

        SignCertRequestDTO request = SignCertRequestDTO.builder().csr("csr-pem").build();

        ManagementNodeException ex =
                assertThrows(ManagementNodeException.class, () -> managementNodeService.signCertificate(request));
        assertEquals("Failed to sign certificate", ex.getMessage());
    }
}
