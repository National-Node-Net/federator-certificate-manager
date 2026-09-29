/*
 * SPDX-License-Identifier: Apache-2.0
 * © Crown Copyright 2026. This work has been developed by the National Digital Twin Programme and is legally
 * attributed to the UK's Department for Business, Innovation, Science and Trade (BIST) as the governing entity.
 */

package uk.gov.dbt.ndtp.federator.certificate.manager;

import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.core.Version;
import com.fasterxml.jackson.databind.cfg.PackageVersion;
import org.junit.jupiter.api.Test;

class JacksonDatabindVersionTest {

    @Test
    void jacksonDatabindVersionIncludesCve202668497Fix() {
        Version version = PackageVersion.VERSION;

        boolean fixedVersion = version.getMajorVersion() > 2
                || (version.getMajorVersion() == 2 && version.getMinorVersion() > 18)
                || (version.getMajorVersion() == 2 && version.getMinorVersion() == 18 && version.getPatchLevel() >= 10);

        assertTrue(fixedVersion, () -> "jackson-databind must be at least 2.18.10, but resolved " + version);
    }
}
