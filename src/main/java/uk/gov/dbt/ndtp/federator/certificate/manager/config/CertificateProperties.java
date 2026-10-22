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
     * The keystore and truststore are written to each configured location: {@code file}, {@code vault}, or both.
     * A location that is not provided (or has a blank path) is skipped.
     */
    @Getter
    @Setter
    public static class Destination {
        /**
         * Name of the keystore password file (file) and of the keystore password attribute (vault).
         */
        public static final String KEYSTORE_PASSWORD_NAME = "keystore.password";

        /**
         * Name of the truststore password file (file) and of the truststore password attribute (vault).
         */
        public static final String TRUSTSTORE_PASSWORD_NAME = "truststore.password";

        /**
         * The password for the PKCS12 keystore, shared by all locations. If not provided, it is resolved from
         * Vault or generated.
         */
        private String keystorePassword;

        /**
         * The password for the PKCS12 truststore, shared by all locations. If not provided, it is resolved from
         * Vault or generated.
         */
        private String truststorePassword;

        /**
         * Filesystem location. The keystore, truststore and password files ({@value #KEYSTORE_PASSWORD_NAME},
         * {@value #TRUSTSTORE_PASSWORD_NAME}) are written under {@code path}.
         */
        private StoreLocation file;

        /**
         * Vault location. {@code path} is a KV v2 secret path whose first segment is the mount
         * (e.g. {@code /secret/app/federator}); the store file names and the password names are used as the
         * attribute names in that secret.
         */
        private StoreLocation vault;
    }

    /**
     * Settings shared by the filesystem and Vault destinations.
     */
    @Getter
    @Setter
    public static class StoreLocation {
        /**
         * The base directory (file) or KV v2 secret path (vault) where the stores are written.
         */
        private String path;

        /**
         * The filename (file) or attribute name (vault) for the PKCS12 keystore.
         */
        private String keystoreFile = "keystore.p12";

        /**
         * The filename (file) or attribute name (vault) for the PKCS12 truststore.
         */
        private String truststoreFile = "truststore.p12";

        /**
         * The alias for the certificate in the keystore.
         */
        private String keystoreAlias = "federator";

        /**
         * @return true when a path is configured, meaning stores should be written to this location
         */
        public boolean isEnabled() {
            return path != null && !path.isBlank();
        }
    }
}
