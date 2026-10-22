/*
 * SPDX-License-Identifier: Apache-2.0
 * © Crown Copyright 2026. This work has been developed by the National Digital Twin Programme and is legally
 * attributed to the UK's Department for Business, Innovation, Science and Trade (BIST) as the governing entity.
 */

package uk.gov.dbt.ndtp.federator.certificate.manager.service;

/**
 * Service for synchronizing keystores and truststores to the configured destinations.
 */
public interface KeyStoreSyncService {
    /**
     * Synchronizes keystores and truststores, built from the Vault certificate material, to each configured
     * destination (filesystem and/or a Vault KV v2 secret).
     */
    void syncKeyStores();
}
