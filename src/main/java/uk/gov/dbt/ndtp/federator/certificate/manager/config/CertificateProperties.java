/*
 * SPDX-License-Identifier: Apache-2.0
 * © Crown Copyright 2026. This work has been developed by the National Digital Twin Programme and is legally
 * attributed to the UK's Department for Business, Innovation, Science and Trade (BIST) as the governing entity.
 */

package uk.gov.dbt.ndtp.federator.certificate.manager.config;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

/**
 * Configuration properties for certificate management.
 * These properties are bound from 'application.certificate' in application.yml.
 */
@Getter
@Setter
@Configuration
@ConfigurationProperties(prefix = "application.certificate")
public class CertificateProperties {

    /**
     * The minimum number of days the intermediate certificate must be valid for.
     */
    private long intermediateMinValidDays = 14;

    /**
     * The threshold percentage of validity remaining below which a certificate should be renewed.
     */
    private double renewalThresholdPercentage = 10.0;

    /**
     * The key size for generated key pairs (e.g., 2048 or 4096).
     */
    private Integer keySize = 2048;

    /**
     * The OID used to identify bootstrap certificates via an otherName SAN entry.
     */
    private String bootstrapOid = "1.3.6.1.4.1.32473.1.1";

    /**
     * The subject details for the certificate.
     */
    private Subject subject = new Subject();

    /**
     * The destination configuration for keystore and truststore.
     */
    private Destination destination = new Destination();

    /**
     * Nested class for certificate subject fields.
     */
    @Getter
    @Setter
    public static class Subject {
        private String country;
        private String state;
        private String locality;
        private String organization;
        private String organizationalUnit;
        private String commonName;
        /**
         * Comma-separated list of alternative names (DNS).
         */
        private String altNames;
    }

    /**
     * Nested class for destination configuration.
     */
    @Getter
    @Setter
    public static class Destination {
        /**
         * The base directory path where all certificate files will be written.
         */
        private String path;

        /**
         * The filename for the PKCS12 keystore.
         */
        private String keystoreFile = "keystore.p12";

        /**
         * The filename for the PKCS12 truststore.
         */
        private String truststoreFile = "truststore.p12";

        /**
         * The password for the PKCS12 keystore. If not provided, it will be generated.
         */
        private String keystorePassword;

        /**
         * The filename for the keystore password.
         */
        private String keystorePasswordFile = "keystore.password";

        /**
         * The password for the PKCS12 truststore. If not provided, it will be generated.
         */
        private String truststorePassword;

        /**
         * The filename for the truststore password.
         */
        private String truststorePasswordFile = "truststore.password";

        /**
         * The alias for the certificate in the keystore.
         */
        private String keystoreAlias = "federator";
    }
}
