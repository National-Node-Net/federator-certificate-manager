/*
 * SPDX-License-Identifier: Apache-2.0
 * © Crown Copyright 2026. This work has been developed by the National Digital Twin Programme and is legally
 * attributed to the UK's Department for Business, Innovation, Science and Trade (BIST) as the governing entity.
 */

package uk.gov.dbt.ndtp.federator.certificate.manager.service;

import java.util.Arrays;
import java.util.List;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import uk.gov.dbt.ndtp.federator.certificate.manager.config.CertificateProperties;
import uk.gov.dbt.ndtp.federator.certificate.manager.model.dto.CertificateResponseDTO;
import uk.gov.dbt.ndtp.federator.certificate.manager.model.dto.CreateCsrRequestDTO;
import uk.gov.dbt.ndtp.federator.certificate.manager.model.dto.CreateCsrResponseDTO;
import uk.gov.dbt.ndtp.federator.certificate.manager.model.dto.CreateKeyResponseDTO;
import uk.gov.dbt.ndtp.federator.certificate.manager.model.dto.SignCertRequestDTO;
import uk.gov.dbt.ndtp.federator.certificate.manager.model.dto.SignCertResponseDTO;
import uk.gov.dbt.ndtp.federator.certificate.manager.service.pki.PkiService;
import uk.gov.dbt.ndtp.federator.certificate.manager.service.pki.VaultSecretProvider;
import uk.gov.dbt.ndtp.federator.certificate.manager.service.pki.cryptography.PemUtil;

/**
 * Service responsible for periodic certificate management tasks.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class CertificateManagerServiceImpl implements CertificateManagerService {

    private static final String RENEW_LOG_MSG = "Starting certificate renewal process";

    private final ManagementNodeService managementNodeService;
    private final PkiService pkiService;
    private final VaultSecretProvider vaultSecretProvider;
    private final CertificateProperties certificateProperties;
    private final KeyStoreSyncService keyStoreSyncService;

    /**
     * Periodically executed task to check certificate status and initiate renewal if necessary.
     * Also ensures the intermediate CA is refreshed.
     */
    @Override
    public void run() {
        // Ensure Intermediate CA is healthy before attempting certificate renewal
        checkAndRefreshIntermediateCa();

        String currentCert = vaultSecretProvider.getCertificate();
        if (currentCert == null || currentCert.isBlank()) {
            log.info("No certificate found in Vault. Initiating renewal...");
            renewCertificate();
        } else if (isBootstrapCertificate(currentCert)) {
            log.info("Bootstrap certificate detected. Initiating immediate renewal...");
            renewCertificate();
        } else {
            long daysLeft = PemUtil.daysUntilExpiry(currentCert);
            String expiryDateStr = getExpiryDateString(currentCert);

            double threshold = certificateProperties.getRenewalThresholdPercentage();
            if (PemUtil.isValidityBelowThreshold(currentCert, threshold)) {
                log.info(
                        "Certificate validity is below {}%. Expiry date: {}, days remaining: {}. Initiating renewal...",
                        threshold, expiryDateStr, daysLeft);
                renewCertificate();
            } else {
                log.info(
                        "Certificate is still valid above threshold. Expiry date: {}, days remaining: {}. Skipping renewal.",
                        expiryDateStr,
                        daysLeft);
            }
        }
    }

    /**
     * Periodically executed task to synchronize on-disk keystores and truststores with Vault.
     */
    @Override
    public void sync() {
        keyStoreSyncService.syncKeyStoresToFilesystem();
    }

    private static String getExpiryDateString(String currentCert) {
        String expiryDateStr;
        try {
            expiryDateStr = PemUtil.parseCertificate(currentCert).getNotAfter().toString();
        } catch (Exception ex) {
            expiryDateStr = "unknown";
        }
        return expiryDateStr;
    }

    private void checkAndRefreshIntermediateCa() {
        String current = vaultSecretProvider.getIntermediateCa();
        boolean missing = (current == null || current.isBlank());
        long minValidDays = certificateProperties.getIntermediateMinValidDays();
        boolean expiringSoon = !missing && !PemUtil.isValidForAtLeastDays(current, minValidDays);

        if (missing || expiringSoon) {
            if (missing) {
                log.warn("Intermediate CA not found in Vault. Requesting a new one from Management Node...");
            } else {
                long daysLeft = PemUtil.daysUntilExpiry(current);
                log.warn(
                        "Intermediate CA expires in {} days (< {} threshold). Requesting a new one...",
                        daysLeft,
                        minValidDays);
            }
            CertificateResponseDTO response = managementNodeService.getIntermediateCertificate();
            if (response != null
                    && response.getCertificate() != null
                    && !response.getCertificate().isBlank()) {
                vaultSecretProvider.persistIntermediateCa(response.getCertificate());
                log.info("Intermediate CA updated and persisted to Vault.");
            } else {
                log.error("Management Node did not return a valid Intermediate CA certificate.");
            }
        } else {
            log.info("Intermediate CA in Vault is valid for at least {} days. No action required.", minValidDays);
        }
    }

    /**
     * Determines whether the given certificate is a bootstrap certificate by checking for
     * a custom OID in the Subject Alternative Name.
     */
    boolean isBootstrapCertificate(String certPem) {
        String bootstrapOid = certificateProperties.getBootstrapOid();
        if (bootstrapOid != null && !bootstrapOid.isBlank() && PemUtil.hasOtherNameSan(certPem, bootstrapOid)) {
            log.debug("Certificate contains bootstrap OID marker: {}", bootstrapOid);
            return true;
        }
        return false;
    }

    /**
     * Executes the certificate renewal workflow: generates new keys, requests a CSR, and sends it for signing.
     */
    void renewCertificate() {
        log.info(RENEW_LOG_MSG);

        CreateKeyResponseDTO keyPair = generateAndPersistKeyPair();
        if (keyPair == null) {
            log.warn("Key pair generation returned null; skipping CSR creation and signing.");
            return;
        }

        CreateCsrResponseDTO csr = createCsr(keyPair);
        if (csr == null || csr.getCsrPem() == null) {
            log.warn("CSR not available; skipping certificate signing request.");
            return;
        }

        SignCertResponseDTO signed = requestSigning(csr);
        if (signed == null) {
            log.warn("Sign certificate response was null");
            return;
        }

        persistSignedArtifacts(signed);
        log.info("Certificate renewal completed successfully.");
    }

    private CreateKeyResponseDTO generateAndPersistKeyPair() {
        CreateKeyResponseDTO keyPairDto = pkiService.createKeyPair(null, certificateProperties.getKeySize());
        if (keyPairDto != null) {
            vaultSecretProvider.persistKeyPair(keyPairDto);
        }
        return keyPairDto;
    }

    private CreateCsrResponseDTO createCsr(CreateKeyResponseDTO keyPairDto) {
        if (keyPairDto == null || keyPairDto.getPublicKeyPem() == null || keyPairDto.getPrivateKeyPem() == null) {
            log.warn("Missing key material; skipping CSR creation.");
            return null;
        }

        CertificateProperties.Subject subjectCfg = certificateProperties.getSubject();
        List<String> dnsSans = null;
        String cfgAltNamesCsv = subjectCfg.getAltNames();
        if (cfgAltNamesCsv != null && !cfgAltNamesCsv.isBlank()) {
            dnsSans = Arrays.stream(cfgAltNamesCsv.split(","))
                    .map(String::trim)
                    .filter(s -> !s.isEmpty())
                    .toList();
        }

        CreateCsrRequestDTO csrReq = CreateCsrRequestDTO.builder()
                .publicKeyPem(keyPairDto.getPublicKeyPem())
                .privateKeyPem(keyPairDto.getPrivateKeyPem())
                .commonName(subjectCfg.getCommonName())
                .organization(subjectCfg.getOrganization())
                .organizationalUnit(subjectCfg.getOrganizationalUnit())
                .country(subjectCfg.getCountry())
                .state(subjectCfg.getState())
                .locality(subjectCfg.getLocality())
                .dnsSans(dnsSans)
                .build();
        return pkiService.createCsr(csrReq);
    }

    private SignCertResponseDTO requestSigning(CreateCsrResponseDTO csrResp) {
        return managementNodeService.signCertificate(
                SignCertRequestDTO.builder().csr(csrResp.getCsrPem()).build());
    }

    private void persistSignedArtifacts(SignCertResponseDTO signResp) {
        String certificate = signResp.getCertificate();
        if (certificate == null || certificate.isBlank()) {
            log.warn("Signed certificate is null/blank; skipping certificate validation and persistence.");
            return;
        }

        if (!isSignedCertificateValid(certificate)) return;

        vaultSecretProvider.persistCertificate(certificate);
        persistCaChain(signResp);
        persistIntermediateCert(signResp);
    }

    private void persistIntermediateCert(SignCertResponseDTO signResp) {
        if (signResp.getIssuingCa() != null && !signResp.getIssuingCa().isBlank()) {
            vaultSecretProvider.persistIntermediateCa(signResp.getIssuingCa());
        } else {
            log.warn("Intermediate CA is null/blank; skipping intermediate CA persistence.");
        }
    }

    private void persistCaChain(SignCertResponseDTO signResp) {
        if (signResp.getCaChain() != null && !signResp.getCaChain().isEmpty()) {
            vaultSecretProvider.persistCaChain(signResp.getCaChain());
        } else {
            log.warn("CA chain is null/empty; skipping CA chain persistence.");
        }
    }

    private boolean isSignedCertificateValid(String certificate) {
        try {
            String intermediateCa = vaultSecretProvider.getIntermediateCa();
            if (intermediateCa != null && !intermediateCa.isBlank()) {
                PemUtil.verifyCertificate(certificate, intermediateCa);
                log.info("Received certificate is valid and verified against Intermediate CA from Vault.");
                return true;

            } else {
                log.warn("Intermediate CA not found in Vault; skipping verification of the received certificate.");
                return true;
            }
        } catch (Exception e) {
            log.error("Certificate verification failed. The certificate will not be persisted.", e);
            return false;
        }
    }
}
