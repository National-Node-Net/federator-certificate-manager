/*
 * SPDX-License-Identifier: Apache-2.0
 * © Crown Copyright 2026. This work has been developed by the National Digital Twin Programme and is legally
 * attributed to the UK's Department for Business, Innovation, Science and Trade (BIST) as the governing entity.
 */

package uk.gov.dbt.ndtp.federator.certificate.manager.service.pki.cryptography;

import static org.junit.jupiter.api.Assertions.*;

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Date;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.Test;
import uk.gov.dbt.ndtp.federator.certificate.manager.exception.PkiException;

class PemUtilTest {

    @Test
    void verifyCertificate_success() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        KeyPair caKeyPair = kpg.generateKeyPair();
        KeyPair leafKeyPair = kpg.generateKeyPair();

        X500Name caName = new X500Name("CN=CA");
        X500Name leafName = new X500Name("CN=Leaf");

        X509Certificate caCert = createCert(caName, caName, caKeyPair.getPublic(), caKeyPair.getPrivate());
        X509Certificate leafCert = createCert(leafName, caName, leafKeyPair.getPublic(), caKeyPair.getPrivate());

        String caPem = PemUtil.toPem("CERTIFICATE", caCert.getEncoded());
        String leafPem = PemUtil.toPem("CERTIFICATE", leafCert.getEncoded());

        PemUtil.verifyCertificate(leafPem, caPem);
    }

    @Test
    void verifyCertificate_failure() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        KeyPair caKeyPair1 = kpg.generateKeyPair();
        KeyPair caKeyPair2 = kpg.generateKeyPair();
        KeyPair leafKeyPair = kpg.generateKeyPair();

        X500Name caName1 = new X500Name("CN=CA1");
        X500Name leafName = new X500Name("CN=Leaf");

        X509Certificate caCert2 = createCert(
                new X500Name("CN=CA2"), new X500Name("CN=CA2"), caKeyPair2.getPublic(), caKeyPair2.getPrivate());
        X509Certificate leafCert = createCert(leafName, caName1, leafKeyPair.getPublic(), caKeyPair1.getPrivate());

        String leafPem = PemUtil.toPem("CERTIFICATE", leafCert.getEncoded());
        String caPem2 = PemUtil.toPem("CERTIFICATE", caCert2.getEncoded());

        assertThrows(PkiException.class, () -> PemUtil.verifyCertificate(leafPem, caPem2));
    }

    @Test
    void daysUntilExpiry_handlesException() {
        assertEquals(Long.MIN_VALUE, PemUtil.daysUntilExpiry("invalid"));
    }

    @Test
    void daysUntilExpiry_returnsPositiveDays() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        KeyPair kp = kpg.generateKeyPair();
        X500Name name = new X500Name("CN=Test");
        long now = System.currentTimeMillis();
        Date start = new Date(now);
        Date end = new Date(now + (1000L * 60 * 60 * 24 * 30)); // 30 days
        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA").build(kp.getPrivate());
        X509v3CertificateBuilder builder =
                new JcaX509v3CertificateBuilder(name, BigInteger.valueOf(now), start, end, name, kp.getPublic());
        X509Certificate cert = new JcaX509CertificateConverter().getCertificate(builder.build(signer));
        String pem = PemUtil.toPem("CERTIFICATE", cert.getEncoded());

        long days = PemUtil.daysUntilExpiry(pem);
        assertTrue(days >= 29);
    }

    @Test
    void verifyCertificate_expiryFailure() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        KeyPair caKeyPair = kpg.generateKeyPair();
        KeyPair leafKeyPair = kpg.generateKeyPair();

        X500Name caName = new X500Name("CN=CA");
        X500Name leafName = new X500Name("CN=Leaf");

        long past = System.currentTimeMillis() - 1000000;
        Date start = new Date(past);
        Date end = new Date(past + 1000);
        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA").build(caKeyPair.getPrivate());
        X509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                caName, BigInteger.valueOf(past), start, end, leafName, leafKeyPair.getPublic());
        X509Certificate expiredCert = new JcaX509CertificateConverter().getCertificate(builder.build(signer));

        X509Certificate caCert = createCert(caName, caName, caKeyPair.getPublic(), caKeyPair.getPrivate());

        String leafPem = PemUtil.toPem("CERTIFICATE", expiredCert.getEncoded());
        String caPem = PemUtil.toPem("CERTIFICATE", caCert.getEncoded());

        assertThrows(PkiException.class, () -> PemUtil.verifyCertificate(leafPem, caPem));
    }

    private X509Certificate createCert(X500Name subject, X500Name issuer, PublicKey pubKey, PrivateKey privKey)
            throws Exception {
        long now = System.currentTimeMillis();
        Date start = new Date(now);
        Date end = new Date(now + 100000);
        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA").build(privKey);
        X509v3CertificateBuilder builder =
                new JcaX509v3CertificateBuilder(issuer, BigInteger.valueOf(now), start, end, subject, pubKey);
        return new JcaX509CertificateConverter().getCertificate(builder.build(signer));
    }

    @Test
    void toPem_and_parse_roundTrip_private_and_public() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        KeyPair kp = kpg.generateKeyPair();

        String privatePem = PemUtil.toPem("PRIVATE KEY", kp.getPrivate().getEncoded());
        String publicPem = PemUtil.toPem("PUBLIC KEY", kp.getPublic().getEncoded());

        PrivateKey parsedPriv = PemUtil.parsePkcs8PrivateKey(privatePem);
        PublicKey parsedPub = PemUtil.parsePublicKey(publicPem);

        assertNotNull(parsedPriv);
        assertNotNull(parsedPub);
        assertEquals("RSA", parsedPriv.getAlgorithm());
        assertEquals("RSA", parsedPub.getAlgorithm());

        PrivateKey reconstructedPriv =
                KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(parsedPriv.getEncoded()));
        PublicKey reconstructedPub =
                KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(parsedPub.getEncoded()));

        assertArrayEquals(reconstructedPriv.getEncoded(), parsedPriv.getEncoded());
        assertArrayEquals(reconstructedPub.getEncoded(), parsedPub.getEncoded());
    }

    @Test
    void toPem_lineWrapping_and_decode_stability() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(1024);
        KeyPair kp = kpg.generateKeyPair();

        String privatePem = PemUtil.toPem("PRIVATE KEY", kp.getPrivate().getEncoded());
        assertTrue(privatePem.contains("-----BEGIN PRIVATE KEY-----"));
        assertTrue(privatePem.contains("-----END PRIVATE KEY-----"));

        PrivateKey parsed = PemUtil.parsePkcs8PrivateKey(privatePem);
        assertNotNull(parsed);
    }

    @Test
    void isValidForAtLeastDays_success() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        KeyPair kp = kpg.generateKeyPair();
        X500Name name = new X500Name("CN=Test");

        long now = System.currentTimeMillis();
        Date start = new Date(now);
        Date end = new Date(now + (1000L * 60 * 60 * 24 * 2)); // 2 days from now
        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA").build(kp.getPrivate());
        X509v3CertificateBuilder builder =
                new JcaX509v3CertificateBuilder(name, BigInteger.valueOf(now), start, end, name, kp.getPublic());
        X509Certificate cert = new JcaX509CertificateConverter().getCertificate(builder.build(signer));

        String pem = PemUtil.toPem("CERTIFICATE", cert.getEncoded());

        assertTrue(PemUtil.isValidForAtLeastDays(pem, 1));
    }

    @Test
    void extractCn_directTest() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        KeyPair caKeyPair = kpg.generateKeyPair();
        KeyPair leafKeyPair = kpg.generateKeyPair();

        // DN with no CN
        X500Name caName = new X500Name("O=Org, C=UK");
        X500Name leafName = new X500Name("CN=Leaf");

        X509Certificate caCert = createCert(caName, caName, caKeyPair.getPublic(), caKeyPair.getPrivate());
        X509Certificate leafCert = createCert(leafName, caName, leafKeyPair.getPublic(), caKeyPair.getPrivate());

        String caPem = PemUtil.toPem("CERTIFICATE", caCert.getEncoded());
        String leafPem = PemUtil.toPem("CERTIFICATE", leafCert.getEncoded());

        // Should work and log "Unknown" for CN
        PemUtil.verifyCertificate(leafPem, caPem);
    }

    @Test
    void parseCertificate_throwsForInvalidPem() {
        assertThrows(PkiException.class, () -> PemUtil.parseCertificate("not-a-cert"));
    }

    @Test
    void parsePkcs8PrivateKey_throwsForInvalidPem() {
        assertThrows(PkiException.class, () -> PemUtil.parsePkcs8PrivateKey("not-a-key"));
    }

    @Test
    void parsePublicKey_throwsForInvalidPem() {
        assertThrows(PkiException.class, () -> PemUtil.parsePublicKey("not-a-key"));
    }

    @Test
    void isValidityBelowThreshold_returnsTrueWhenBelowThreshold() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        KeyPair kp = kpg.generateKeyPair();
        X500Name name = new X500Name("CN=Test");

        long now = System.currentTimeMillis();
        // Total: 100 days. Elapsed: 95 days. Remaining: 5 days (~5%)
        Date start = new Date(now - 3600000L * 24 * 95);
        Date end = new Date(now + 3600000L * 24 * 5);
        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA").build(kp.getPrivate());
        X509v3CertificateBuilder builder =
                new JcaX509v3CertificateBuilder(name, BigInteger.valueOf(now), start, end, name, kp.getPublic());
        X509Certificate cert = new JcaX509CertificateConverter().getCertificate(builder.build(signer));
        String pem = PemUtil.toPem("CERTIFICATE", cert.getEncoded());

        assertTrue(PemUtil.isValidityBelowThreshold(pem, 10.0));
    }

    @Test
    void isValidityBelowThreshold_returnsFalseWhenAboveThreshold() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        KeyPair kp = kpg.generateKeyPair();
        X500Name name = new X500Name("CN=Test");

        long now = System.currentTimeMillis();
        // Total: 100 days. Elapsed: 5 days. Remaining: 95 days (~95%)
        Date start = new Date(now - 3600000L * 24 * 5);
        Date end = new Date(now + 3600000L * 24 * 95);
        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA").build(kp.getPrivate());
        X509v3CertificateBuilder builder =
                new JcaX509v3CertificateBuilder(name, BigInteger.valueOf(now), start, end, name, kp.getPublic());
        X509Certificate cert = new JcaX509CertificateConverter().getCertificate(builder.build(signer));
        String pem = PemUtil.toPem("CERTIFICATE", cert.getEncoded());

        assertFalse(PemUtil.isValidityBelowThreshold(pem, 10.0));
    }

    @Test
    void isValidityBelowThreshold_returnsTrueForInvalidPem() {
        assertTrue(PemUtil.isValidityBelowThreshold("invalid-pem", 10.0));
    }

    @Test
    void hasOtherNameSan_returnsTrueWhenOidPresent() throws Exception {
        String oid = "1.3.6.1.4.1.32473.1.1";
        String pem = createCertWithOtherNameSan(oid, "bootstrap");
        assertTrue(PemUtil.hasOtherNameSan(pem, oid));
    }

    @Test
    void hasOtherNameSan_returnsFalseWhenDifferentOid() throws Exception {
        String pem = createCertWithOtherNameSan("1.3.6.1.4.1.32473.1.1", "bootstrap");
        assertFalse(PemUtil.hasOtherNameSan(pem, "1.3.6.1.4.1.99999.1.1"));
    }

    @Test
    void hasOtherNameSan_returnsFalseWhenNoSans() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        KeyPair kp = kpg.generateKeyPair();
        X509Certificate cert =
                createCert(new X500Name("CN=NoSans"), new X500Name("CN=CA"), kp.getPublic(), kp.getPrivate());
        String pem = PemUtil.toPem("CERTIFICATE", cert.getEncoded());
        assertFalse(PemUtil.hasOtherNameSan(pem, "1.3.6.1.4.1.32473.1.1"));
    }

    @Test
    void hasOtherNameSan_returnsTrueWhenMultipleOidsPresent() throws Exception {
        String targetOid = "1.3.6.1.4.1.32473.1.1";
        String otherOid = "1.3.6.1.4.1.32473.2.1";
        String pem = createCertWithMultipleOtherNameSans(otherOid, "something", targetOid, "bootstrap");
        assertTrue(PemUtil.hasOtherNameSan(pem, targetOid));
    }

    @Test
    void hasOtherNameSan_returnsFalseForInvalidPem() {
        assertFalse(PemUtil.hasOtherNameSan("not-a-cert", "1.3.6.1.4.1.32473.1.1"));
    }

    private String createCertWithOtherNameSan(String oid, String value) throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        KeyPair kp = kpg.generateKeyPair();
        X500Name name = new X500Name("CN=Test");
        long now = System.currentTimeMillis();
        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA").build(kp.getPrivate());

        org.bouncycastle.asn1.DERSequence otherNameSeq =
                new org.bouncycastle.asn1.DERSequence(new org.bouncycastle.asn1.ASN1Encodable[] {
                    new ASN1ObjectIdentifier(oid), new DERTaggedObject(true, 0, new DERUTF8String(value))
                });
        GeneralName otherName = new GeneralName(GeneralName.otherName, otherNameSeq);
        GeneralNames sans = new GeneralNames(otherName);

        X509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                name, BigInteger.valueOf(now), new Date(now), new Date(now + 100000), name, kp.getPublic());
        builder.addExtension(Extension.subjectAlternativeName, false, sans);

        X509Certificate cert = new JcaX509CertificateConverter().getCertificate(builder.build(signer));
        return PemUtil.toPem("CERTIFICATE", cert.getEncoded());
    }

    private String createCertWithMultipleOtherNameSans(String oid1, String value1, String oid2, String value2)
            throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        KeyPair kp = kpg.generateKeyPair();
        X500Name name = new X500Name("CN=Test");
        long now = System.currentTimeMillis();
        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA").build(kp.getPrivate());

        GeneralName san1 = new GeneralName(
                GeneralName.otherName, new org.bouncycastle.asn1.DERSequence(new org.bouncycastle.asn1.ASN1Encodable[] {
                    new ASN1ObjectIdentifier(oid1), new DERTaggedObject(true, 0, new DERUTF8String(value1))
                }));
        GeneralName san2 = new GeneralName(
                GeneralName.otherName, new org.bouncycastle.asn1.DERSequence(new org.bouncycastle.asn1.ASN1Encodable[] {
                    new ASN1ObjectIdentifier(oid2), new DERTaggedObject(true, 0, new DERUTF8String(value2))
                }));
        GeneralNames sans = new GeneralNames(new GeneralName[] {san1, san2});

        X509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                name, BigInteger.valueOf(now), new Date(now), new Date(now + 100000), name, kp.getPublic());
        builder.addExtension(Extension.subjectAlternativeName, false, sans);

        X509Certificate cert = new JcaX509CertificateConverter().getCertificate(builder.build(signer));
        return PemUtil.toPem("CERTIFICATE", cert.getEncoded());
    }
}
