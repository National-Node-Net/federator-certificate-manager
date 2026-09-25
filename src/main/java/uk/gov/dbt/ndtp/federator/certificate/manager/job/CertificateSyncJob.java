/*
 * SPDX-License-Identifier: Apache-2.0
 * © Crown Copyright 2026. This work has been developed by the National Digital Twin Programme and is legally
 * attributed to the UK's Department for Business, Innovation, Science and Trade (BIST) as the governing entity.
 */

package uk.gov.dbt.ndtp.federator.certificate.manager.job;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;
import uk.gov.dbt.ndtp.federator.certificate.manager.service.CertificateManagerService;

/**
 * Job responsible for periodically synchronizing keystores and truststores to the filesystem.
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class CertificateSyncJob {

    private final CertificateManagerService certificateManagerService;

    /**
     * Periodically executed task to synchronize on-disk keystores and truststores with Vault.
     */
    @Scheduled(
            fixedDelayString = "${application.scheduling.certificate-manager.sync-rate}",
            initialDelayString = "${application.scheduling.certificate-manager.sync-initial-delay:5000}")
    public void execute() {
        log.debug("Executing Certificate Sync Job");
        try {
            certificateManagerService.sync();
        } catch (Exception e) {
            log.error("Error during certificate synchronization job execution: {}", e.getMessage(), e);
        }
    }
}
