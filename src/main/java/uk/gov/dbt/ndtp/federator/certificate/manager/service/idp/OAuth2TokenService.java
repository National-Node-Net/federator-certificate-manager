/*
 * SPDX-License-Identifier: Apache-2.0
 * © Crown Copyright 2026. This work has been developed by the National Digital Twin Programme and is legally
 * attributed to the UK's Department for Business, Innovation, Science and Trade (BIST) as the governing entity.
 */

package uk.gov.dbt.ndtp.federator.certificate.manager.service.idp;

import uk.gov.dbt.ndtp.federator.certificate.manager.exception.OAuth2TokenException;

/**
 * Contract for services that can obtain OAuth2 access tokens from an Identity Provider.
 */
public interface OAuth2TokenService {

    /**
     * Requests a new OAuth2 access token using the configured grant and client credentials.
     *
     * @return a {@link TokenResponse} containing the access token and its expiration time in seconds
     * @throws OAuth2TokenException if the token request fails or the response is invalid
     */
    TokenResponse getAccessToken();
}
