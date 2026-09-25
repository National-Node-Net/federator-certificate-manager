/*
 * SPDX-License-Identifier: Apache-2.0
 * © Crown Copyright 2026. This work has been developed by the National Digital Twin Programme and is legally
 * attributed to the UK's Department for Business, Innovation, Science and Trade (BIST) as the governing entity.
 */

package uk.gov.dbt.ndtp.federator.certificate.manager.job;

import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import uk.gov.dbt.ndtp.federator.certificate.manager.service.CertificateManagerService;

@ExtendWith(MockitoExtension.class)
class CertificateRenewalJobTest {

    @Mock
    private CertificateManagerService certificateManagerService;

    @InjectMocks
    private CertificateRenewalJob certificateRenewalJob;

    @Test
    void execute_callsServiceRun() {
        certificateRenewalJob.execute();
        verify(certificateManagerService, times(1)).run();
    }

    @Test
    void execute_handlesServiceException() {
        doThrow(new RuntimeException("Service failed"))
                .when(certificateManagerService)
                .run();

        // Should not throw exception
        certificateRenewalJob.execute();

        verify(certificateManagerService, times(1)).run();
    }
}
