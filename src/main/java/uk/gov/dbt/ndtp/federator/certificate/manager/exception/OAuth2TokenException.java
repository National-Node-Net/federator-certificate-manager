/*
 * SPDX-License-Identifier: Apache-2.0
 * © Crown Copyright 2026. This work has been developed by the National Digital Twin Programme and is legally
 * attributed to the UK's Department for Business, Innovation, Science and Trade (BIST) as the governing entity.
 */

package uk.gov.dbt.ndtp.federator.certificate.manager.exception;

/**
 * Custom exception thrown when OAuth2 token retrieval or processing fails.
 */
public class OAuth2TokenException extends RuntimeException {

    /**
     * Constructs a new OAuth2TokenException with the specified detail message.
     *
     * @param message the detail message
     */
    public OAuth2TokenException(String message) {
        super(message);
    }

    /**
     * Constructs a new OAuth2TokenException with the specified detail message and cause.
     *
     * @param message the detail message
     * @param cause the cause of the exception
     */
    public OAuth2TokenException(String message, Throwable cause) {
        super(message, cause);
    }
}
