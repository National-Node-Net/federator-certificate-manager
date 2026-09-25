/*
 * SPDX-License-Identifier: Apache-2.0
 * © Crown Copyright 2026. This work has been developed by the National Digital Twin Programme and is legally
 * attributed to the UK's Department for Business, Innovation, Science and Trade (BIST) as the governing entity.
 */

package uk.gov.dbt.ndtp.federator.certificate.manager.exception;

/**
 * Exception thrown when there is an error during the creation or processing of a {@link java.security.KeyStore}.
 */
public class KeyStoreCreationException extends RuntimeException {
    /**
     * Constructs a new KeyStoreCreationException with the specified detail message.
     *
     * @param message the detail message
     */
    public KeyStoreCreationException(String message) {
        super(message);
    }

    /**
     * Constructs a new KeyStoreCreationException with the specified detail message and cause.
     *
     * @param message the detail message
     * @param cause the cause of the exception
     */
    public KeyStoreCreationException(String message, Throwable cause) {
        super(message, cause);
    }
}
