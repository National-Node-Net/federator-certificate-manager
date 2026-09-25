/*
 * SPDX-License-Identifier: Apache-2.0
 * © Crown Copyright 2026. This work has been developed by the National Digital Twin Programme and is legally
 * attributed to the UK's Department for Business, Innovation, Science and Trade (BIST) as the governing entity.
 */

package uk.gov.dbt.ndtp.federator.certificate.manager.service.pki;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.time.Instant;
import java.util.UUID;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.springframework.stereotype.Service;
import uk.gov.dbt.ndtp.federator.certificate.manager.exception.PkiException;
import uk.gov.dbt.ndtp.federator.certificate.manager.model.dto.CreateCsrRequestDTO;
import uk.gov.dbt.ndtp.federator.certificate.manager.model.dto.CreateCsrResponseDTO;
import uk.gov.dbt.ndtp.federator.certificate.manager.model.dto.CreateKeyResponseDTO;
import uk.gov.dbt.ndtp.federator.certificate.manager.service.pki.cryptography.PemUtil;

/**
 * Service for managing PKI operations using HashiCorp Vault.
 * Provides functionality for creating key pairs, CSRs, signing CSRs, and retrieving intermediate certificates.
 */
@Service
@Slf4j
public class PkiService {

    /**
     * Creates a new RSA or specified algorithm key pair.
     *
     * @param algorithm the key algorithm (defaults to RSA if null or blank)
     * @param keySize the size of the key (defaults to 2048 if null)
     * @return a DTO containing the public and private key in PEM format
     * @throws PkiException if key pair generation fails
     */
    public CreateKeyResponseDTO createKeyPair(String algorithm, Integer keySize) {
        String alg = (algorithm == null || algorithm.isBlank()) ? "RSA" : algorithm;
        int size = (keySize == null) ? 2048 : keySize;

        log.info("Creating key pair with algorithm: {} and size: {}", alg, size);
        try {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance(alg);
            if ("RSA".equalsIgnoreCase(alg)) {
                kpg.initialize(size);
            }
            KeyPair kp = kpg.generateKeyPair();

            String privateKeyPem = PemUtil.toPem("PRIVATE KEY", kp.getPrivate().getEncoded());
            String publicKeyPem = PemUtil.toPem("PUBLIC KEY", kp.getPublic().getEncoded());

            return CreateKeyResponseDTO.builder()
                    .createdAt(Instant.now().toString())
                    .algorithm(alg)
                    .publicKeyPem(publicKeyPem)
                    .privateKeyPem(privateKeyPem)
                    .build();
        } catch (NoSuchAlgorithmException e) {
            log.error("Failed to create key pair: algorithm {} not found", alg, e);
            throw new PkiException("Key pair generation failed: " + alg, e);
        }
    }

    /**
     * Creates a Certificate Signing Request (CSR) from provided public and private keys and subject information.
     *
     * @param req the CSR request DTO containing keys and subject details
     * @return a DTO containing the generated CSR PEM and a unique ID
     * @throws PkiException if CSR creation or signing fails
     */
    public CreateCsrResponseDTO createCsr(CreateCsrRequestDTO req) {
        log.info("Creating CSR for common name: {}", req.getCommonName());
        try {
            String privateKeyPem = req.getPrivateKeyPem();
            String publicKeyPem = req.getPublicKeyPem();

            PrivateKey privateKey = PemUtil.parsePkcs8PrivateKey(privateKeyPem);
            var publicKey = PemUtil.parsePublicKey(publicKeyPem);

            // Build subject including State (ST) and Locality (L); blank RDNs are omitted
            // (Bouncy Castle 1.85+ rejects empty values such as a zero-length country code).
            String subject = java.util.stream.Stream.of(
                            rdn("C", req.getCountry()),
                            rdn("ST", req.getState()),
                            rdn("L", req.getLocality()),
                            rdn("O", req.getOrganization()),
                            rdn("OU", req.getOrganizationalUnit()),
                            rdn("CN", req.getCommonName()))
                    .filter(java.util.Objects::nonNull)
                    .collect(java.util.stream.Collectors.joining(", "));
            X500Name x500 = new X500Name(subject);

            // CSR builder
            JcaPKCS10CertificationRequestBuilder csrBuilder = new JcaPKCS10CertificationRequestBuilder(x500, publicKey);

            // SANs
            java.util.List<String> dnsSans = req.getDnsSans();
            if (dnsSans != null && !dnsSans.isEmpty()) {
                log.debug("Adding DNS SANs to CSR: {}", dnsSans);
                GeneralNames sans = new GeneralNames(dnsSans.stream()
                        .map(d -> new GeneralName(GeneralName.dNSName, d))
                        .toArray(GeneralName[]::new));
                csrBuilder.addAttribute(
                        PKCSObjectIdentifiers.pkcs_9_at_extensionRequest,
                        new Extensions(new Extension(Extension.subjectAlternativeName, false, sans.getEncoded())));
            }

            ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA").build(privateKey);
            PKCS10CertificationRequest csr = csrBuilder.build(signer);

            String csrPem = PemUtil.toPem("CERTIFICATE REQUEST", csr.getEncoded());
            String csrId = UUID.randomUUID().toString();

            return new CreateCsrResponseDTO(csrId, csrPem);
        } catch (Exception e) {
            log.error("Failed to create CSR for subject common name: {}", req.getCommonName(), e);
            throw new PkiException("CSR creation failed", e);
        }
    }

    /**
     * Safely formats a subject component by replacing commas with spaces.
     *
     * @param s the string to safe format
     * @return the safe string or empty string if null
     */
    private static String safe(String s) {
        return (s == null) ? "" : s.replace(",", " ");
    }

    private static String rdn(String type, String value) {
        String v = safe(value).trim();
        return v.isEmpty() ? null : type + "=" + v;
    }
}
