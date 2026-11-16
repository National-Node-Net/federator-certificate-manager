/*
 * SPDX-License-Identifier: Apache-2.0
 * © Crown Copyright 2026. This work has been developed by the National Digital Twin Programme and is legally
 * attributed to the UK's Department for Business, Innovation, Science and Trade (BIST) as the governing entity.
 */

package uk.gov.dbt.ndtp.federator.certificate.manager.service.pki.cryptography;

import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.concurrent.atomic.AtomicLong;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

/**
 * Test fixture: a three-level PKI ({@code root -> intermediate -> leaf}) plus helpers to issue extra certificates.
 */
public final class TestPkiHierarchy {

    private static final AtomicLong SERIAL = new AtomicLong(System.currentTimeMillis());

    public final Issued root;
    public final Issued intermediate;
    public final Issued leaf;

    public TestPkiHierarchy() {
        root = selfSigned("CN=Test Root CA");
        intermediate = issue("CN=Test Intermediate CA", root);
        leaf = issue("CN=Test Leaf", intermediate);
    }

    /** A certificate together with the key pair it certifies. */
    public record Issued(X509Certificate certificate, KeyPair keyPair) {

        public String pem() {
            try {
                return PemUtil.toPem("CERTIFICATE", certificate.getEncoded());
            } catch (GeneralSecurityException e) {
                throw new IllegalStateException(e);
            }
        }

        public String privateKeyPem() {
            return PemUtil.toPem("PRIVATE KEY", keyPair.getPrivate().getEncoded());
        }
    }

    public static Issued selfSigned(String subject) {
        KeyPair keyPair = newKeyPair();
        return new Issued(sign(subject, subject, keyPair, keyPair), keyPair);
    }

    public static Issued issue(String subject, Issued issuer) {
        KeyPair keyPair = newKeyPair();
        String issuerName = issuer.certificate().getSubjectX500Principal().getName();
        return new Issued(sign(subject, issuerName, keyPair, issuer.keyPair()), keyPair);
    }

    private static X509Certificate sign(String subject, String issuer, KeyPair subjectKeys, KeyPair issuerKeys) {
        Instant now = Instant.now();
        try {
            var builder = new JcaX509v3CertificateBuilder(
                    new X500Name(issuer),
                    BigInteger.valueOf(SERIAL.incrementAndGet()),
                    Date.from(now.minus(Duration.ofMinutes(1))),
                    Date.from(now.plus(Duration.ofDays(1))),
                    new X500Name(subject),
                    subjectKeys.getPublic());
            var signer = new JcaContentSignerBuilder("SHA256withRSA").build(issuerKeys.getPrivate());
            return new JcaX509CertificateConverter().getCertificate(builder.build(signer));
        } catch (OperatorCreationException | GeneralSecurityException e) {
            throw new IllegalStateException("Failed to create test certificate", e);
        }
    }

    private static KeyPair newKeyPair() {
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
            generator.initialize(2048);
            return generator.generateKeyPair();
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }
}
