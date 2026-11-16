/*
 * SPDX-License-Identifier: Apache-2.0
 * © Crown Copyright 2026. This work has been developed by the National Digital Twin Programme and is legally
 * attributed to the UK's Department for Business, Innovation, Science and Trade (BIST) as the governing entity.
 */

package uk.gov.dbt.ndtp.federator.certificate.manager;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mockStatic;

import org.junit.jupiter.api.Test;
import org.mockito.MockedStatic;
import org.springframework.boot.SpringApplication;

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

    @Test
    void mainStartsTheSpringApplication() {
        String[] args = {"--spring.profiles.active=test"};
        try (MockedStatic<SpringApplication> spring = mockStatic(SpringApplication.class)) {
            CertificateManagerApplication.main(args);

            spring.verify(() -> SpringApplication.run(CertificateManagerApplication.class, args));
        }
    }
}
