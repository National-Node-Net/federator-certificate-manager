/*
 * SPDX-License-Identifier: Apache-2.0
 * © Crown Copyright 2026. This work has been developed by the National Digital Twin Programme and is legally
 * attributed to the UK's Department for Business, Innovation, Science and Trade (BIST) as the governing entity.
 */

package uk.gov.dbt.ndtp.federator.certificate.manager.service.idp;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import org.apache.hc.client5.http.impl.classic.CloseableHttpClient;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.MediaType;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestClient;
import uk.gov.dbt.ndtp.federator.certificate.manager.client.MtlsHttpClientBuilder;
import uk.gov.dbt.ndtp.federator.certificate.manager.exception.OAuth2TokenException;

@ExtendWith(MockitoExtension.class)
class OAuth2TokenServiceImplTest {

    @Test
    void getAccessToken_returnsTokenResponse() {
        MtlsHttpClientBuilder builder = mock(MtlsHttpClientBuilder.class);
        CloseableHttpClient httpClient = mock(CloseableHttpClient.class);
        RestClient restClient = mock(RestClient.class, RETURNS_DEEP_STUBS);
        when(builder.buildHttpClient()).thenReturn(httpClient);

        Map<String, Object> payload = new HashMap<>();
        payload.put("access_token", "srv-token");
        payload.put("expires_in", 900);

        when(restClient
                        .post()
                        .uri(anyString())
                        .contentType(any(MediaType.class))
                        .body(any(MultiValueMap.class))
                        .retrieve()
                        .body(any(ParameterizedTypeReference.class)))
                .thenReturn(payload);

        OAuth2TokenServiceImpl service = new OAuth2TokenServiceImpl(builder, "https://example/token", "CLIENT");
        service = spy(service);
        doReturn(restClient).when(service).buildRestClient(httpClient);

        TokenResponse response = service.getAccessToken();

        assertEquals("srv-token", response.getAccessToken());
        assertEquals(900, response.getExpiresIn());
    }

    @Test
    void getAccessToken_throwsExceptionWhenAccessTokenMissing() {
        MtlsHttpClientBuilder builder = mock(MtlsHttpClientBuilder.class);
        CloseableHttpClient httpClient = mock(CloseableHttpClient.class);
        RestClient restClient = mock(RestClient.class, RETURNS_DEEP_STUBS);
        when(builder.buildHttpClient()).thenReturn(httpClient);

        when(restClient
                        .post()
                        .uri(anyString())
                        .contentType(any(MediaType.class))
                        .body(any(MultiValueMap.class))
                        .retrieve()
                        .body(any(ParameterizedTypeReference.class)))
                .thenReturn(Collections.emptyMap());

        OAuth2TokenServiceImpl service = new OAuth2TokenServiceImpl(builder, "https://example/token", "CLIENT");
        service = spy(service);
        doReturn(restClient).when(service).buildRestClient(httpClient);

        assertThrows(OAuth2TokenException.class, service::getAccessToken);
    }

    @Test
    void getAccessToken_throwsExceptionWhenResponseIsNull() {
        MtlsHttpClientBuilder builder = mock(MtlsHttpClientBuilder.class);
        CloseableHttpClient httpClient = mock(CloseableHttpClient.class);
        RestClient restClient = mock(RestClient.class, RETURNS_DEEP_STUBS);
        when(builder.buildHttpClient()).thenReturn(httpClient);

        when(restClient
                        .post()
                        .uri(anyString())
                        .contentType(any(MediaType.class))
                        .body(any(MultiValueMap.class))
                        .retrieve()
                        .body(any(ParameterizedTypeReference.class)))
                .thenReturn(null);

        OAuth2TokenServiceImpl service = new OAuth2TokenServiceImpl(builder, "https://example/token", "CLIENT");
        service = spy(service);
        doReturn(restClient).when(service).buildRestClient(httpClient);

        assertThrows(OAuth2TokenException.class, service::getAccessToken);
    }

    @Test
    void getAccessToken_throwsExceptionWhenRestClientFails() {
        MtlsHttpClientBuilder builder = mock(MtlsHttpClientBuilder.class);
        CloseableHttpClient httpClient = mock(CloseableHttpClient.class);
        RestClient restClient = mock(RestClient.class, RETURNS_DEEP_STUBS);
        when(builder.buildHttpClient()).thenReturn(httpClient);

        when(restClient
                        .post()
                        .uri(anyString())
                        .contentType(any(MediaType.class))
                        .body(any(MultiValueMap.class))
                        .retrieve()
                        .body(any(ParameterizedTypeReference.class)))
                .thenThrow(new RuntimeException("Network error"));

        OAuth2TokenServiceImpl service = new OAuth2TokenServiceImpl(builder, "https://example/token", "CLIENT");
        service = spy(service);
        doReturn(restClient).when(service).buildRestClient(httpClient);

        assertThrows(OAuth2TokenException.class, service::getAccessToken);
    }
}
