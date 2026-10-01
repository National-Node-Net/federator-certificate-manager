/*
 * SPDX-License-Identifier: Apache-2.0
 * © Crown Copyright 2026. This work has been developed by the National Digital Twin Programme and is legally
 * attributed to the UK's Department for Business, Innovation, Science and Trade (BIST) as the governing entity.
 */

package uk.gov.dbt.ndtp.federator.certificate.manager.service;

/**
 * Service for synchronizing keystores and truststores to the file system.
 */
public interface KeyStoreSyncService {
    /**
     * Synchronizes keystores and truststores to the file system based on configuration and Vault secrets.
     */
    void syncKeyStoresToFilesystem();
}
