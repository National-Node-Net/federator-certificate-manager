/*
 * SPDX-License-Identifier: Apache-2.0
 * © Crown Copyright 2026. This work has been developed by the National Digital Twin Programme and is legally
 * attributed to the UK's Department for Business, Innovation, Science and Trade (BIST) as the governing entity.
 */

package uk.gov.dbt.ndtp.federator.certificate.manager;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

class CertificateManagerApplicationTest {

    @Test
    void startingMsgConstantIsSet() {
        assertNotNull(CertificateManagerApplication.STARTING_MSG);
        assertEquals("Starting federator Certificate Management service", CertificateManagerApplication.STARTING_MSG);
    }

    @Test
    void classNameIsCorrect() {
        assertEquals("CertificateManagerApplication", CertificateManagerApplication.class.getSimpleName());
    }

    @Test
    void classHasSpringBootAnnotation() {
        assertTrue(CertificateManagerApplication.class.isAnnotationPresent(
                org.springframework.boot.autoconfigure.SpringBootApplication.class));
    }

    @Test
    void classIsNotAnnotatedWithEnableScheduling() {
        // EnableScheduling should be on SchedulingConfig, not the main application class
        assertTrue(!CertificateManagerApplication.class.isAnnotationPresent(
                org.springframework.scheduling.annotation.EnableScheduling.class));
    }
}
