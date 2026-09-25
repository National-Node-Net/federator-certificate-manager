/*
 * SPDX-License-Identifier: Apache-2.0
 * © Crown Copyright 2026. This work has been developed by the National Digital Twin Programme and is legally
 * attributed to the UK's Department for Business, Innovation, Science and Trade (BIST) as the governing entity.
 */

package uk.gov.dbt.ndtp.federator.certificate.manager.service.pki.cryptography;

import java.io.ByteArrayInputStream;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.Collection;
import java.util.List;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;
import uk.gov.dbt.ndtp.federator.certificate.manager.exception.PkiException;

@Slf4j
public final class PemUtil {

    private PemUtil() {
        // Utility class
    }

    private static final String KEY_ALG = "RSA";
    private static final int SAN_TYPE_OTHER_NAME = 0;

    /**
     * Parses a PKCS#8 encoded private key from a PEM string.
     *
     * @param pem the private key in PEM format
     * @return the parsed PrivateKey
     * @throws Exception if parsing fails
     */
    public static PrivateKey parsePkcs8PrivateKey(String pem) {
        try {
            byte[] der = decodePem(pem);
            return KeyFactory.getInstance(KEY_ALG).generatePrivate(new PKCS8EncodedKeySpec(der));
        } catch (Exception e) {
            throw new PkiException("Failed to parse PKCS#8 private key", e);
        }
    }

    /**
     * Parses an X.509 encoded public key from a PEM string.
     *
     * @param pem the public key in PEM format
     * @return the parsed PublicKey
     * @throws Exception if parsing fails
     */
    public static PublicKey parsePublicKey(String pem) {
        try {
            byte[] der = decodePem(pem);
            return KeyFactory.getInstance(KEY_ALG).generatePublic(new X509EncodedKeySpec(der));
        } catch (Exception e) {
            throw new PkiException("Failed to parse public key", e);
        }
    }

    private static byte[] decodePem(String pem) {
        String cleaned = pem.replaceAll("-----BEGIN ([A-Z ]+)-----", "")
                .replaceAll("-----END ([A-Z ]+)-----", "")
                .replaceAll("\\s", "");
        return Base64.getDecoder().decode(cleaned);
    }

    /**
     * Converts raw DER bytes to a PEM-formatted string with headers and footers.
     *
     * @param type the type of the artifact (e.g., "CERTIFICATE", "PRIVATE KEY")
     * @param der the raw DER-encoded bytes
     * @return the PEM string
     */
    public static String toPem(String type, byte[] der) {
        String b64 = Base64.getMimeEncoder(64, new byte[] {'\n'}).encodeToString(der);
        return "-----BEGIN " + type + "-----\n" + b64 + "\n-----END " + type + "-----\n";
    }

    /**
     * Parses an X.509 certificate from a PEM string.
     *
     * @param pem the certificate in PEM format
     * @return the parsed X509Certificate
     * @throws Exception if parsing fails
     */
    public static X509Certificate parseCertificate(String pem) {
        try {
            byte[] der = decodePem(pem);
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            return (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(der));
        } catch (Exception e) {
            throw new PkiException("Failed to parse X.509 certificate", e);
        }
    }

    /**
     * Calculates the number of days remaining until the certificate expires.
     *
     * @param pem the certificate in PEM format
     * @return the number of days until expiry, or Long.MIN_VALUE if parsing fails
     */
    public static long daysUntilExpiry(String pem) {
        try {
            X509Certificate cert = parseCertificate(pem);
            Instant now = Instant.now();
            Instant notAfter = cert.getNotAfter().toInstant();
            return now.until(notAfter, ChronoUnit.DAYS);
        } catch (Exception e) {
            log.warn("Failed to calculate days until expiry: {}", e.getMessage());
            return Long.MIN_VALUE; // indicates invalid/unparseable certificate
        }
    }

    /**
     * Checks if the certificate is valid for at least the specified number of days.
     *
     * @param pem the certificate in PEM format
     * @param minDays the minimum required validity in days
     * @return true if the certificate is valid for at least minDays, false otherwise
     */
    public static boolean isValidForAtLeastDays(String pem, long minDays) {
        long days = daysUntilExpiry(pem);
        return days >= minDays;
    }

    /**
     * Verifies that a certificate was signed by the specified issuer.
     * Also checks the certificate's current validity period.
     *
     * @param certificatePem the certificate to verify in PEM format
     * @param issuerPem the issuer's certificate in PEM format
     * @throws Exception if verification fails or the certificate is invalid
     */
    public static void verifyCertificate(String certificatePem, String issuerPem) {
        try {
            X509Certificate cert = parseCertificate(certificatePem);
            X509Certificate issuer = parseCertificate(issuerPem);

            String certSubject = cert.getSubjectX500Principal().getName();
            String issuerSubject = issuer.getSubjectX500Principal().getName();
            String issuerCn = extractCn(issuerSubject);

            log.debug("Certificate for {} is validated against Intermediate Cert CN {}", certSubject, issuerCn);
            log.debug("Certificate Issue Date: {}", cert.getNotBefore());
            log.debug("Certificate Expiry Date: {}", cert.getNotAfter());
            log.debug("Verified against Issuer Subject: {}", issuerSubject);

            // Check both validity and expiry against time
            cert.checkValidity();

            // Signature verification
            cert.verify(issuer.getPublicKey());
        } catch (PkiException e) {
            throw e;
        } catch (Exception e) {
            throw new PkiException("Failed to verify certificate against issuer", e);
        }
    }

    /**
     * Checks if the certificate's remaining validity percentage is below the given threshold.
     *
     * @param pem the certificate in PEM format
     * @param thresholdPercentage the renewal threshold percentage (e.g., 10.0)
     * @return true if renewal is recommended, false otherwise
     */
    public static boolean isValidityBelowThreshold(String pem, double thresholdPercentage) {
        try {
            X509Certificate cert = parseCertificate(pem);
            long now = Instant.now().toEpochMilli();
            long notBefore = cert.getNotBefore().getTime();
            long notAfter = cert.getNotAfter().getTime();

            long totalDuration = notAfter - notBefore;
            long remainingDuration = notAfter - now;

            if (totalDuration <= 0) {
                return true;
            }

            double percentageRemaining = (double) remainingDuration / totalDuration * 100;
            return percentageRemaining <= thresholdPercentage;
        } catch (Exception e) {
            log.warn("Failed to check validity threshold: {}", e.getMessage());
            return true; // If unparseable, assume it needs renewal
        }
    }

    /**
     * Checks whether the certificate contains an otherName SAN entry with the specified OID.
     *
     * @param certPem the certificate in PEM format
     * @param oid the OID to look for (e.g., "1.3.6.1.4.1.32473.1.1")
     * @return true if the certificate has an otherName SAN matching the OID
     */
    public static boolean hasOtherNameSan(String certPem, String oid) {
        try {
            X509Certificate cert = parseCertificate(certPem);
            Collection<List<?>> sans = cert.getSubjectAlternativeNames();
            if (sans == null) {
                return false;
            }
            for (List<?> san : sans) {
                if (san.size() >= 2 && Integer.valueOf(SAN_TYPE_OTHER_NAME).equals(san.get(0))) {
                    byte[] derBytes = (byte[]) san.get(1);
                    if (otherNameMatchesOid(derBytes, oid)) {
                        return true;
                    }
                }
            }
            return false;
        } catch (Exception e) {
            log.warn("Failed to check otherName SANs: {}", e.getMessage());
            return false;
        }
    }

    private static boolean otherNameMatchesOid(byte[] derBytes, String expectedOid) {
        try (ASN1InputStream asn1In = new ASN1InputStream(derBytes)) {
            ASN1Sequence seq = ASN1Sequence.getInstance(asn1In.readObject());
            if (seq.size() >= 1) {
                ASN1ObjectIdentifier actualOid = ASN1ObjectIdentifier.getInstance(seq.getObjectAt(0));
                return expectedOid.equals(actualOid.getId());
            }
        } catch (Exception e) {
            log.debug("Failed to parse otherName ASN.1: {}", e.getMessage());
        }
        return false;
    }

    private static String extractCn(String dn) {
        if (dn == null || dn.isBlank()) {
            return "Unknown";
        }
        try {
            javax.naming.ldap.LdapName ldapName = new javax.naming.ldap.LdapName(dn);
            for (javax.naming.ldap.Rdn rdn : ldapName.getRdns()) {
                if ("CN".equalsIgnoreCase(rdn.getType())) {
                    return rdn.getValue().toString();
                }
            }
        } catch (Exception e) {
            log.warn("Failed to extract CN from DN: {}. Error: {}", dn, e.getMessage());
        }
        return "Unknown";
    }
}
