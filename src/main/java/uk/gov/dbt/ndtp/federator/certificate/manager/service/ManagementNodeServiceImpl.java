/*
 * SPDX-License-Identifier: Apache-2.0
 * © Crown Copyright 2026. This work has been developed by the National Digital Twin Programme and is legally
 * attributed to the UK's Department for Business, Innovation, Science and Trade (BIST) as the governing entity.
 */

package uk.gov.dbt.ndtp.federator.certificate.manager.service;

import io.github.resilience4j.circuitbreaker.annotation.CircuitBreaker;
import io.github.resilience4j.retry.annotation.Retry;
import lombok.extern.slf4j.Slf4j;
import org.apache.hc.client5.http.impl.classic.CloseableHttpClient;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.client.HttpComponentsClientHttpRequestFactory;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestClient;
import uk.gov.dbt.ndtp.federator.certificate.manager.client.MtlsHttpClientBuilder;
import uk.gov.dbt.ndtp.federator.certificate.manager.exception.ManagementNodeException;
import uk.gov.dbt.ndtp.federator.certificate.manager.model.dto.CertificateResponseDTO;
import uk.gov.dbt.ndtp.federator.certificate.manager.model.dto.SignCertRequestDTO;
import uk.gov.dbt.ndtp.federator.certificate.manager.model.dto.SignCertResponseDTO;
import uk.gov.dbt.ndtp.federator.certificate.manager.service.idp.TokenCacheService;

/**
 * Implementation of the ManagementNodeService for interacting with Management Node APIs.
 * Uses mTLS and Bearer token authentication.
 */
@Slf4j
@Service
public class ManagementNodeServiceImpl implements ManagementNodeService {

    public static final String INTERMEDIATE_CERT_PATH = "/api/v1/certificate/intermediate";
    public static final String SIGN_CSR_PATH = "/api/v1/certificate/csr/sign";
    public static final String BEARER_PREFIX = "Bearer ";

    private final MtlsHttpClientBuilder httpClientBuilder;
    private final TokenCacheService tokenCacheService;
    private final String baseUrl;

    /**
     * Constructs the ManagementNodeServiceImpl.
     *
     * @param tokenCacheService the service providing cached OAuth2 tokens
     * @param baseUrl the base URL of the Management Node
     * @param httpClientBuilder a builder which can create instances of {@link CloseableHttpClient}
     */
    public ManagementNodeServiceImpl(
            TokenCacheService tokenCacheService,
            @Value("${application.management-node.base-url}") String baseUrl,
            MtlsHttpClientBuilder httpClientBuilder) {
        this.tokenCacheService = tokenCacheService;
        this.baseUrl = baseUrl;
        this.httpClientBuilder = httpClientBuilder;
    }

    /**
     * Retrieves the intermediate certificate from the Management Node.
     *
     * @return the certificate response
     * @throws ManagementNodeException if the API call fails
     */
    @Retry(name = "management-node")
    @CircuitBreaker(name = "management-node")
    @Override
    public CertificateResponseDTO getIntermediateCertificate() {
        String token = tokenCacheService.getToken();
        String url = baseUrl + INTERMEDIATE_CERT_PATH;

        log.debug("Requesting intermediate certificate from {}", url);

        try (CloseableHttpClient httpClient = httpClientBuilder.buildHttpClient()) {
            RestClient restClient = buildRestClient(httpClient);
            return restClient
                    .get()
                    .uri(url)
                    .header(HttpHeaders.AUTHORIZATION, BEARER_PREFIX + token)
                    .retrieve()
                    .body(CertificateResponseDTO.class);
        } catch (Exception e) {
            throw new ManagementNodeException("Failed to retrieve intermediate certificate", e);
        }
    }

    /**
     * Sends a CSR to be signed by the Management Node.
     *
     * @param request CSR request
     * @return signed certificate response
     */
    @Retry(name = "management-node")
    @CircuitBreaker(name = "management-node")
    @Override
    public SignCertResponseDTO signCertificate(SignCertRequestDTO request) {
        String token = tokenCacheService.getToken();
        String url = baseUrl + SIGN_CSR_PATH;

        log.debug("Requesting certificate signing from {}", url);

        try (CloseableHttpClient httpClient = httpClientBuilder.buildHttpClient()) {
            RestClient restClient = buildRestClient(httpClient);
            return restClient
                    .post()
                    .uri(url)
                    .header(HttpHeaders.AUTHORIZATION, BEARER_PREFIX + token)
                    .body(request)
                    .retrieve()
                    .body(SignCertResponseDTO.class);
        } catch (Exception e) {
            throw new ManagementNodeException("Failed to sign certificate", e);
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
