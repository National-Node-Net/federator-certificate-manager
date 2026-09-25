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
 * Job responsible for periodically checking and renewing certificates.
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class CertificateRenewalJob {

    private final CertificateManagerService certificateManagerService;

    /**
     * Periodically executed task to check certificate status and initiate renewal if necessary.
     */
    @Scheduled(
            fixedDelayString = "${application.scheduling.certificate-manager.renewal-rate}",
            initialDelayString = "${application.scheduling.certificate-manager.renewal-initial-delay:10000}")
    public void execute() {
        log.debug("Executing Certificate Renewal Job");
        try {
            certificateManagerService.run();
        } catch (Exception e) {
            log.error("Error during certificate renewal job execution: {}", e.getMessage(), e);
        }
    }
}
