/*
 * SPDX-License-Identifier: Apache-2.0
 * © Crown Copyright 2026. This work has been developed by the National Digital Twin Programme and is legally
 * attributed to the UK's Department for Business, Innovation, Science and Trade (BIST) as the governing entity.
 */

package uk.gov.dbt.ndtp.federator.certificate.manager.service.idp;

import uk.gov.dbt.ndtp.federator.certificate.manager.exception.OAuth2TokenException;

/**
 * Contract for services that provide cached access to OAuth2 tokens.
 */
public interface TokenCacheService {

    /**
     * Returns the current access token, using a cached value when available.
     *
     * @return the current JWT access token
     * @throws OAuth2TokenException if the token cannot be retrieved or refreshed
     */
    String getToken();

    /**
     * Forces a refresh of the access token from the identity provider and updates the cache.
     *
     * @return the new JWT access token
     * @throws OAuth2TokenException if the token refresh fails
     */
    String refreshToken();
}
