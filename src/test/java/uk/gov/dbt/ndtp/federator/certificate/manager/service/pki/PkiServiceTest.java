/*
 * SPDX-License-Identifier: Apache-2.0
 * © Crown Copyright 2026. This work has been developed by the National Digital Twin Programme and is legally
 * attributed to the UK's Department for Business, Innovation, Science and Trade (BIST) as the governing entity.
 */

package uk.gov.dbt.ndtp.federator.certificate.manager.service.pki;

import static org.junit.jupiter.api.Assertions.*;

import java.util.List;
import org.junit.jupiter.api.Test;
import uk.gov.dbt.ndtp.federator.certificate.manager.exception.PkiException;
import uk.gov.dbt.ndtp.federator.certificate.manager.model.dto.CreateCsrRequestDTO;
import uk.gov.dbt.ndtp.federator.certificate.manager.model.dto.CreateCsrResponseDTO;
import uk.gov.dbt.ndtp.federator.certificate.manager.model.dto.CreateKeyResponseDTO;

class PkiServiceTest {

    private final PkiService pkiService = new PkiService();

    @Test
    void createKeyPair_success() {
        CreateKeyResponseDTO response = pkiService.createKeyPair("RSA", 2048);
        assertNotNull(response);
        assertEquals("RSA", response.getAlgorithm());
        assertTrue(response.getPrivateKeyPem().contains("-----BEGIN PRIVATE KEY-----"));
    }

    @Test
    void createKeyPair_defaultValues() {
        CreateKeyResponseDTO response = pkiService.createKeyPair(null, null);
        assertNotNull(response);
        assertEquals("RSA", response.getAlgorithm());

        response = pkiService.createKeyPair(" ", null);
        assertEquals("RSA", response.getAlgorithm());
    }

    @Test
    void createKeyPair_verifyPublicKeyPemFormat() {
        CreateKeyResponseDTO response = pkiService.createKeyPair("RSA", 2048);
        assertNotNull(response.getPublicKeyPem());
        assertTrue(response.getPublicKeyPem().contains("-----BEGIN PUBLIC KEY-----"));
        assertTrue(response.getPublicKeyPem().contains("-----END PUBLIC KEY-----"));
    }

    @Test
    void createKeyPair_throwsForInvalidAlgorithm() {
        assertThrows(PkiException.class, () -> pkiService.createKeyPair("INVALID_ALGO", 2048));
    }

    @Test
    void createCsr_success() {
        CreateKeyResponseDTO keyPair = pkiService.createKeyPair("RSA", 2048);

        CreateCsrRequestDTO req = CreateCsrRequestDTO.builder()
                .commonName("test.com, Ltd") // with comma
                .organization("NDTP")
                .organizationalUnit("IT")
                .country("UK")
                .privateKeyPem(keyPair.getPrivateKeyPem())
                .publicKeyPem(keyPair.getPublicKeyPem())
                .dnsSans(List.of("alt.test.com"))
                .build();

        CreateCsrResponseDTO response = pkiService.createCsr(req);
        assertNotNull(response);
        assertTrue(response.getCsrPem().contains("-----BEGIN CERTIFICATE REQUEST-----"));
    }

    @Test
    void createCsr_verifyCsrId() {
        CreateKeyResponseDTO keyPair = pkiService.createKeyPair("RSA", 2048);

        CreateCsrRequestDTO req = CreateCsrRequestDTO.builder()
                .commonName("test.com")
                .privateKeyPem(keyPair.getPrivateKeyPem())
                .publicKeyPem(keyPair.getPublicKeyPem())
                .build();

        CreateCsrResponseDTO response = pkiService.createCsr(req);
        assertNotNull(response.getCsrId());
        assertFalse(response.getCsrId().isBlank());
    }

    @Test
    void createCsr_noSans() {
        CreateKeyResponseDTO keyPair = pkiService.createKeyPair("RSA", 2048);

        CreateCsrRequestDTO req = CreateCsrRequestDTO.builder()
                .commonName("test.com")
                .privateKeyPem(keyPair.getPrivateKeyPem())
                .publicKeyPem(keyPair.getPublicKeyPem())
                .dnsSans(null)
                .build();

        CreateCsrResponseDTO response = pkiService.createCsr(req);
        assertNotNull(response);

        req.setDnsSans(List.of());
        response = pkiService.createCsr(req);
        assertNotNull(response);
    }

    @Test
    void createCsr_failure() {
        CreateCsrRequestDTO req = CreateCsrRequestDTO.builder()
                .commonName("test.com")
                .privateKeyPem("invalid")
                .publicKeyPem("invalid")
                .build();

        assertThrows(PkiException.class, () -> pkiService.createCsr(req));
    }
}
