/*
 * SPDX-License-Identifier: Apache-2.0
 * © Crown Copyright 2026. This work has been developed by the National Digital Twin Programme and is legally
 * attributed to the UK's Department for Business, Innovation, Science and Trade (BIST) as the governing entity.
 */

package uk.gov.dbt.ndtp.federator.certificate.manager.config;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Map;
import org.junit.jupiter.api.Test;
import org.springframework.boot.context.properties.bind.Binder;
import org.springframework.boot.context.properties.source.MapConfigurationPropertySource;

class CertificatePropertiesTest {

    private static CertificateProperties bind(Map<String, String> properties) {
        return new Binder(new MapConfigurationPropertySource(properties))
                .bind("application.certificate", CertificateProperties.class)
                .orElseGet(CertificateProperties::new);
    }

    @Test
    void bindsFileAndVaultDestinations() {
        CertificateProperties properties = bind(Map.of(
                "application.certificate.destination.keystore-password", "ks-pass",
                "application.certificate.destination.file.path", "/tmp/secrets/",
                "application.certificate.destination.file.keystore-file", "client.p12",
                "application.certificate.destination.vault.path", "/secret/app/federator",
                "application.certificate.destination.truststore-password", "ts-pass",
                "application.certificate.destination.vault.keystore-alias", "vault-alias"));

        CertificateProperties.Destination destination = properties.getDestination();
        assertEquals("ks-pass", destination.getKeystorePassword());
        assertTrue(destination.getFile().isEnabled());
        assertEquals("/tmp/secrets/", destination.getFile().getPath());
        assertEquals("client.p12", destination.getFile().getKeystoreFile());
        assertEquals("truststore.p12", destination.getFile().getTruststoreFile());
        assertTrue(destination.getVault().isEnabled());
        assertEquals("/secret/app/federator", destination.getVault().getPath());
        assertEquals("ts-pass", destination.getTruststorePassword());
        assertEquals("vault-alias", destination.getVault().getKeystoreAlias());
        assertEquals("keystore.p12", destination.getVault().getKeystoreFile());
    }

    @Test
    void missingSectionIsNotConfigured() {
        CertificateProperties properties =
                bind(Map.of("application.certificate.destination.file.path", "/tmp/secrets/"));

        assertTrue(properties.getDestination().getFile().isEnabled());
        assertNull(properties.getDestination().getVault());
    }

    @Test
    void blankPathDisablesLocation() {
        CertificateProperties.StoreLocation location = new CertificateProperties.StoreLocation();
        assertFalse(location.isEnabled());
        location.setPath("   ");
        assertFalse(location.isEnabled());
        location.setPath("/secret/app/federator");
        assertTrue(location.isEnabled());
    }

    @Test
    void passwordsAreOnlyConfiguredOnceForAllDestinations() {
        CertificateProperties properties = bind(Map.of(
                "application.certificate.destination.file.path", "/tmp/secrets/",
                "application.certificate.destination.vault.path", "/secret/app/federator"));

        assertNull(properties.getDestination().getKeystorePassword());
        assertNull(properties.getDestination().getTruststorePassword());
        assertEquals("keystore.password", CertificateProperties.Destination.KEYSTORE_PASSWORD_NAME);
        assertEquals("truststore.password", CertificateProperties.Destination.TRUSTSTORE_PASSWORD_NAME);
    }
}
