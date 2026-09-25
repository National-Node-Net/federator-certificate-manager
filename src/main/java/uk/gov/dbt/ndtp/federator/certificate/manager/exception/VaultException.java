/*
 * SPDX-License-Identifier: Apache-2.0
 * © Crown Copyright 2026. This work has been developed by the National Digital Twin Programme and is legally
 * attributed to the UK's Department for Business, Innovation, Science and Trade (BIST) as the governing entity.
 */

package uk.gov.dbt.ndtp.federator.certificate.manager.exception;

/**
 * Exception thrown when interactions with HashiCorp Vault fail.
 */
public class VaultException extends RuntimeException {

    /**
     * Constructs a new VaultException with the specified detail message.
     *
     * @param message the detail message
     */
    public VaultException(String message) {
        super(message);
    }

    /**
     * Constructs a new VaultException with the specified detail message and cause.
     *
     * @param message the detail message
     * @param cause the cause of the exception
     */
    public VaultException(String message, Throwable cause) {
        super(message, cause);
    }
}
