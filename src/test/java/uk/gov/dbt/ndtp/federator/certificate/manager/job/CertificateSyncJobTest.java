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
class CertificateSyncJobTest {

    @Mock
    private CertificateManagerService certificateManagerService;

    @InjectMocks
    private CertificateSyncJob certificateSyncJob;

    @Test
    void execute_callsServiceSync() {
        certificateSyncJob.execute();
        verify(certificateManagerService, times(1)).sync();
    }

    @Test
    void execute_handlesServiceException() {
        doThrow(new RuntimeException("Service failed"))
                .when(certificateManagerService)
                .sync();

        // Should not throw exception
        certificateSyncJob.execute();

        verify(certificateManagerService, times(1)).sync();
    }
}
