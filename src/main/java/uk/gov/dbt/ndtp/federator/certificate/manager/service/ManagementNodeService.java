/*
 * SPDX-License-Identifier: Apache-2.0
 * © Crown Copyright 2026. This work has been developed by the National Digital Twin Programme and is legally
 * attributed to the UK's Department for Business, Innovation, Science and Trade (BIST) as the governing entity.
 */

package uk.gov.dbt.ndtp.federator.certificate.manager.service;

import uk.gov.dbt.ndtp.federator.certificate.manager.exception.ManagementNodeException;
import uk.gov.dbt.ndtp.federator.certificate.manager.model.dto.CertificateResponseDTO;
import uk.gov.dbt.ndtp.federator.certificate.manager.model.dto.SignCertRequestDTO;
import uk.gov.dbt.ndtp.federator.certificate.manager.model.dto.SignCertResponseDTO;

/**
 * Service for interacting with the Management Node APIs.
 */
public interface ManagementNodeService {

    /**
     * Retrieves the intermediate certificate from the Management Node.
     *
     * @return a {@link CertificateResponseDTO} containing the certificate data
     * @throws ManagementNodeException if the retrieval fails
     */
    CertificateResponseDTO getIntermediateCertificate();

    /**
     * Sends a CSR to the Management Node to be signed.
     *
     * @param request the request containing the CSR in PEM format
     * @return the signed certificate response
     * @throws ManagementNodeException if the signing request fails
     */
    SignCertResponseDTO signCertificate(SignCertRequestDTO request);
}
