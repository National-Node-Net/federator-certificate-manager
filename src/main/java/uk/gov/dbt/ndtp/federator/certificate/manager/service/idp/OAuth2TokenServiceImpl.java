/*
 * SPDX-License-Identifier: Apache-2.0
 * © Crown Copyright 2026. This work has been developed by the National Digital Twin Programme and is legally
 * attributed to the UK's Department for Business, Innovation, Science and Trade (BIST) as the governing entity.
 */

package uk.gov.dbt.ndtp.federator.certificate.manager.service.idp;

import io.github.resilience4j.circuitbreaker.annotation.CircuitBreaker;
import io.github.resilience4j.retry.annotation.Retry;
import java.util.Map;
import lombok.extern.slf4j.Slf4j;
import org.apache.hc.client5.http.impl.classic.CloseableHttpClient;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.MediaType;
import org.springframework.http.client.HttpComponentsClientHttpRequestFactory;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestClient;
import uk.gov.dbt.ndtp.federator.certificate.manager.client.MtlsHttpClientBuilder;
import uk.gov.dbt.ndtp.federator.certificate.manager.exception.OAuth2TokenException;

/**
 * Service for requesting OAuth2 tokens from Keycloak using client credentials grant.
 * Communication is secured via mTLS.
 */
@Slf4j
@Service
public class OAuth2TokenServiceImpl implements OAuth2TokenService {
    public static final String GRANT_TYPE = "grant_type";
    public static final String CLIENT_CREDENTIALS = "client_credentials";
    public static final String CLIENT_ID = "client_id";
    public static final String ACCESS_TOKEN = "access_token";
    public static final String EXPIRES_IN = "expires_in";

    private final MtlsHttpClientBuilder httpClientBuilder;
    private final String tokenUri;
    private final String clientId;

    /**
     * Constructs the OAuth2TokenServiceImpl.
     *
     * @param httpClientBuilder a builder which can create instances of {@link CloseableHttpClient}
     * @param tokenUri the URI for requesting the token
     * @param clientId the OAuth2 client identifier
     */
    public OAuth2TokenServiceImpl(
            MtlsHttpClientBuilder httpClientBuilder,
            @Value("${application.oauth2.token-uri}") String tokenUri,
            @Value("${application.oauth2.client-id}") String clientId) {
        this.httpClientBuilder = httpClientBuilder;
        this.tokenUri = tokenUri;
        this.clientId = clientId;
    }

    /**
     * Requests a new OAuth2 access token using client credentials.
     *
     * @return a TokenResponse containing the access token and expiration time
     * @throws OAuth2TokenException if the token request fails or the response is invalid
     */
    @Retry(name = "oauth2")
    @CircuitBreaker(name = "oauth2")
    @Override
    public TokenResponse getAccessToken() {
        log.debug("Requesting OAuth2 token from {}", tokenUri);
        MultiValueMap<String, String> formData = new LinkedMultiValueMap<>();
        formData.add(GRANT_TYPE, CLIENT_CREDENTIALS);
        formData.add(CLIENT_ID, clientId);

        try (CloseableHttpClient httpClient = httpClientBuilder.buildHttpClient()) {
            RestClient restClient = buildRestClient(httpClient);
            Map<String, Object> response = restClient
                    .post()
                    .uri(tokenUri)
                    .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                    .body(formData)
                    .retrieve()
                    .body(new ParameterizedTypeReference<Map<String, Object>>() {});

            if (response != null && response.containsKey(ACCESS_TOKEN)) {
                String token = (String) response.get(ACCESS_TOKEN);
                long expiresIn = ((Number) response.getOrDefault(EXPIRES_IN, 0)).longValue();
                log.info("Successfully retrieved access token, expires in {} seconds", expiresIn);
                return new TokenResponse(token, expiresIn);
            } else {
                log.error(
                        "Token response did not contain access_token: {}",
                        response != null ? response.keySet() : "null");
                throw new OAuth2TokenException("Failed to retrieve access token. Missing access_token in response.");
            }
        } catch (OAuth2TokenException e) {
            throw e;
        } catch (Exception e) {
            log.error("Error retrieving OAuth2 token", e);
            throw new OAuth2TokenException("Error retrieving OAuth2 token", e);
        }
    }

    /**
     * Creates an instance of {@link RestClient} from a {@link CloseableHttpClient}.
     * @param httpClient an instance of {@link CloseableHttpClient}
     * @return an instance of {@link RestClient}
     */
    protected RestClient buildRestClient(CloseableHttpClient httpClient) {
        return RestClient.builder()
                .requestFactory(new HttpComponentsClientHttpRequestFactory(httpClient))
                .build();
    }
}
