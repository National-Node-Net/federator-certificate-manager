/*
 * SPDX-License-Identifier: Apache-2.0
 * © Crown Copyright 2026. This work has been developed by the National Digital Twin Programme and is legally
 * attributed to the UK's Department for Business, Innovation, Science and Trade (BIST) as the governing entity.
 */

package uk.gov.dbt.ndtp.federator.certificate.manager.service.idp;

import java.time.Instant;
import lombok.Getter;
import lombok.ToString;

/**
 * Immutable value object representing an OAuth2 access token response.
 */
@Getter
@ToString(exclude = "accessToken")
public class TokenResponse {
    private final String accessToken;
    private final long expiresIn;
    private final Instant expiryInstant;

    /**
     * Creates a new {@code TokenResponse}.
     *
     * @param accessToken the JWT access token value; must not be null
     * @param expiresIn the token lifetime in seconds
     */
    public TokenResponse(String accessToken, long expiresIn) {
        this.accessToken = accessToken;
        this.expiresIn = expiresIn;
        this.expiryInstant = Instant.now().plusSeconds(expiresIn);
    }

    /**
     * Checks if the token will expire within the specified seconds.
     *
     * @param seconds the threshold in seconds
     * @return true if the token expires within the threshold, false otherwise
     */
    public boolean expiresWithin(long seconds) {
        return Instant.now().plusSeconds(seconds).isAfter(expiryInstant);
    }
}
