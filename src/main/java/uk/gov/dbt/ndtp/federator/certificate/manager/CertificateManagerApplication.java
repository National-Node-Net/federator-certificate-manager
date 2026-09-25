/*
 * SPDX-License-Identifier: Apache-2.0
 * © Crown Copyright 2026. This work has been developed by the National Digital Twin Programme and is legally
 * attributed to the UK's Department for Business, Innovation, Science and Trade (BIST) as the governing entity.
 */

package uk.gov.dbt.ndtp.federator.certificate.manager;

import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * Main application class for the Federator Certificate Management service.
 * This class initializes the Spring Boot application.
 */
@Slf4j
@SpringBootApplication
public class CertificateManagerApplication {
    public static final String STARTING_MSG = "Starting federator Certificate Management service";

    /**
     * The main entry point for the application.
     *
     * @param args command line arguments
     */
    public static void main(final String[] args) {
        log.info(STARTING_MSG);
        SpringApplication.run(CertificateManagerApplication.class, args);
    }
}
