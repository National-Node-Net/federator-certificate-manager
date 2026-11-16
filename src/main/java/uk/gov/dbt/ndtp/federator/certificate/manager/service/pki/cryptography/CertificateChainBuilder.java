/*
 * SPDX-License-Identifier: Apache-2.0
 * © Crown Copyright 2026. This work has been developed by the National Digital Twin Programme and is legally
 * attributed to the UK's Department for Business, Innovation, Science and Trade (BIST) as the governing entity.
 */

package uk.gov.dbt.ndtp.federator.certificate.manager.service.pki.cryptography;

import java.security.GeneralSecurityException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import lombok.extern.slf4j.Slf4j;

/**
 * Builds the ordered certificate chain for a keystore key entry.
 *
 * <p>The CA chain received from the management node may hold several certificates in any order, and may include
 * certificates that are not part of the leaf's issuing path (for example another federator's CA). A PKCS12 key entry,
 * however, requires an ordered path where each certificate is issued by the next one, with no duplicates. This class
 * walks from the leaf up through its issuers, using only the supplied CA certificates, and returns that path.
 *
 * <p>Certificates not on the path are left out of the key entry; they are still trusted through the truststore.
 */
@Slf4j
public final class CertificateChainBuilder {

    private CertificateChainBuilder() {
        // Utility class
    }

    /**
     * Builds the ordered chain {@code [leaf, issuer, issuer's issuer, ...]} from PEM input.
     *
     * @param leafPem the leaf certificate in PEM format
     * @param caChainPems the CA certificates in PEM format, in any order; may be {@code null}
     * @return the ordered chain, always starting with the leaf
     */
    public static List<X509Certificate> build(String leafPem, List<String> caChainPems) {
        X509Certificate leaf = PemUtil.parseCertificate(leafPem);
        List<X509Certificate> caCertificates = caChainPems == null
                ? List.of()
                : caChainPems.stream().map(PemUtil::parseCertificate).toList();
        return build(leaf, caCertificates);
    }

    /**
     * Builds the ordered chain {@code [leaf, issuer, issuer's issuer, ...]}.
     * The walk stops at a self-signed certificate or when no issuer can be found among the CA certificates.
     *
     * @param leaf the leaf certificate
     * @param caCertificates the CA certificates, in any order
     * @return the ordered chain, always starting with the leaf
     */
    public static List<X509Certificate> build(X509Certificate leaf, List<X509Certificate> caCertificates) {
        Set<X509Certificate> candidates = new LinkedHashSet<>(caCertificates); // drops duplicates
        candidates.remove(leaf);

        List<X509Certificate> chain = new ArrayList<>();
        chain.add(leaf);
        X509Certificate current = leaf;
        while (!isSelfSigned(current)) {
            Optional<X509Certificate> issuer = findIssuer(current, candidates);
            if (issuer.isEmpty()) {
                logMissingIssuer(current, chain.size() == 1 && !candidates.isEmpty());
                break;
            }
            chain.add(issuer.get());
            candidates.remove(issuer.get());
            current = issuer.get();
        }

        logUnusedCertificates(candidates);
        return chain;
    }

    private static Optional<X509Certificate> findIssuer(X509Certificate certificate, Set<X509Certificate> candidates) {
        return candidates.stream()
                .filter(candidate -> candidate.getSubjectX500Principal().equals(certificate.getIssuerX500Principal()))
                .filter(candidate -> isSignedBy(certificate, candidate))
                .findFirst();
    }

    private static boolean isSelfSigned(X509Certificate certificate) {
        return certificate.getSubjectX500Principal().equals(certificate.getIssuerX500Principal())
                && isSignedBy(certificate, certificate);
    }

    /**
     * Checks the signature as well as the name, so that a CA re-keyed under the same name (e.g. during rotation) is not
     * mistaken for the real issuer.
     */
    private static boolean isSignedBy(X509Certificate certificate, X509Certificate issuer) {
        try {
            certificate.verify(issuer.getPublicKey());
            return true;
        } catch (GeneralSecurityException e) {
            return false;
        }
    }

    private static void logMissingIssuer(X509Certificate certificate, boolean leafIssuerMissing) {
        String issuer = certificate.getIssuerX500Principal().getName();
        if (leafIssuerMissing) {
            log.warn(
                    "CA chain does not contain the issuer of the leaf certificate ({}). "
                            + "Keystore will hold the leaf certificate only.",
                    issuer);
        } else {
            log.debug(
                    "Certificate chain ends at {}; its issuer ({}) is not in the CA chain.",
                    certificate.getSubjectX500Principal().getName(),
                    issuer);
        }
    }

    private static void logUnusedCertificates(Set<X509Certificate> unused) {
        unused.forEach(certificate -> log.debug(
                "CA certificate {} is not on the leaf's issuing path; left out of the keystore chain.",
                certificate.getSubjectX500Principal().getName()));
    }
}
