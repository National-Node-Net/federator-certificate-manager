/*
 * SPDX-License-Identifier: Apache-2.0
 * © Crown Copyright 2026. This work has been developed by the National Digital Twin Programme and is legally
 * attributed to the UK's Department for Business, Innovation, Science and Trade (BIST) as the governing entity.
 */

package uk.gov.dbt.ndtp.federator.certificate.manager.service;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.*;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.List;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERSequence;
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
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import uk.gov.dbt.ndtp.federator.certificate.manager.config.CertificateProperties;
import uk.gov.dbt.ndtp.federator.certificate.manager.exception.PkiException;
import uk.gov.dbt.ndtp.federator.certificate.manager.model.dto.CertificateResponseDTO;
import uk.gov.dbt.ndtp.federator.certificate.manager.model.dto.CreateCsrResponseDTO;
import uk.gov.dbt.ndtp.federator.certificate.manager.model.dto.CreateKeyResponseDTO;
import uk.gov.dbt.ndtp.federator.certificate.manager.model.dto.SignCertResponseDTO;
import uk.gov.dbt.ndtp.federator.certificate.manager.service.pki.PkiService;
import uk.gov.dbt.ndtp.federator.certificate.manager.service.pki.VaultSecretProvider;
import uk.gov.dbt.ndtp.federator.certificate.manager.service.pki.cryptography.PemUtil;

@ExtendWith(MockitoExtension.class)
class CertificateManagerServiceImplTest {

    @Mock
    private ManagementNodeService managementNodeService;

    @Mock
    private PkiService pkiService;

    @Mock
    private VaultSecretProvider vaultSecretProvider;

    @Mock
    private KeyStoreSyncService keyStoreSyncService;

    private CertificateProperties certificateProperties;

    @InjectMocks
    private CertificateManagerServiceImpl certificateManagerService;

    @BeforeEach
    void setUp() {
        certificateProperties = new CertificateProperties();
        certificateProperties.setRenewalThresholdPercentage(10.0);
        certificateProperties.setKeySize(2048);
        certificateProperties.getSubject().setCommonName("api.acme-digital.co.uk");
        certificateProperties.getSubject().setCountry("UK");
        certificateManagerService = new CertificateManagerServiceImpl(
                managementNodeService, pkiService, vaultSecretProvider, certificateProperties, keyStoreSyncService);
    }

    @Test
    void run_checksIntermediateCaAndRenews() {
        when(managementNodeService.getIntermediateCertificate())
                .thenReturn(CertificateResponseDTO.builder().build());

        certificateManagerService.run();

        verify(vaultSecretProvider, times(1)).getIntermediateCa();
        verify(managementNodeService, times(1)).getIntermediateCertificate();
        verify(pkiService, times(1)).createKeyPair(null, 2048);
    }

    @Test
    void run_handlesExceptionByPropagating() {
        when(vaultSecretProvider.getIntermediateCa()).thenThrow(new RuntimeException("vault failure"));

        // After removing outer try-catch, exceptions propagate
        assertThrows(RuntimeException.class, () -> certificateManagerService.run());

        verify(vaultSecretProvider, times(1)).getIntermediateCa();
    }

    @Test
    void renewCertificate_success() {
        CreateKeyResponseDTO keyPair = CreateKeyResponseDTO.builder()
                .publicKeyPem("pub")
                .privateKeyPem("priv")
                .build();
        CreateCsrResponseDTO csr = new CreateCsrResponseDTO("id", "csr-pem");
        SignCertResponseDTO signed =
                SignCertResponseDTO.builder().certificate("cert-pem").build();

        when(pkiService.createKeyPair(null, 2048)).thenReturn(keyPair);
        when(pkiService.createCsr(any())).thenReturn(csr);
        when(managementNodeService.signCertificate(any())).thenReturn(signed);
        when(vaultSecretProvider.getIntermediateCa()).thenReturn(null); // skip verification

        certificateManagerService.renewCertificate();

        verify(pkiService, times(1)).createKeyPair(null, 2048);
        verify(vaultSecretProvider, times(1)).persistKeyPair(keyPair);
        verify(vaultSecretProvider, times(1)).persistCertificate("cert-pem");
    }

    @Test
    void renewCertificate_skipsWhenKeyPairIsNull() {
        when(pkiService.createKeyPair(null, 2048)).thenReturn(null);

        certificateManagerService.renewCertificate();

        verify(pkiService, times(1)).createKeyPair(null, 2048);
        verify(vaultSecretProvider, never()).persistKeyPair(any());
        verify(managementNodeService, never()).signCertificate(any());
    }

    @Test
    void renewCertificate_skipsWhenCsrIsNull() {
        CreateKeyResponseDTO keyPair = CreateKeyResponseDTO.builder()
                .publicKeyPem("pub")
                .privateKeyPem("priv")
                .build();
        when(pkiService.createKeyPair(null, 2048)).thenReturn(keyPair);
        when(pkiService.createCsr(any())).thenReturn(null);

        certificateManagerService.renewCertificate();

        verify(managementNodeService, never()).signCertificate(any());
    }

    @Test
    void renewCertificate_skipsWhenSignResponseIsNull() {
        CreateKeyResponseDTO keyPair = CreateKeyResponseDTO.builder()
                .publicKeyPem("pub")
                .privateKeyPem("priv")
                .build();
        CreateCsrResponseDTO csr = new CreateCsrResponseDTO("id", "csr-pem");
        when(pkiService.createKeyPair(null, 2048)).thenReturn(keyPair);
        when(pkiService.createCsr(any())).thenReturn(csr);
        when(managementNodeService.signCertificate(any())).thenReturn(null);

        certificateManagerService.renewCertificate();

        verify(vaultSecretProvider, never()).persistCertificate(any());
    }

    @Test
    void renewCertificate_skipsWhenCertificateIsBlank() {
        CreateKeyResponseDTO keyPair = CreateKeyResponseDTO.builder()
                .publicKeyPem("pub")
                .privateKeyPem("priv")
                .build();
        CreateCsrResponseDTO csr = new CreateCsrResponseDTO("id", "csr-pem");
        SignCertResponseDTO signed =
                SignCertResponseDTO.builder().certificate("   ").build();

        when(pkiService.createKeyPair(null, 2048)).thenReturn(keyPair);
        when(pkiService.createCsr(any())).thenReturn(csr);
        when(managementNodeService.signCertificate(any())).thenReturn(signed);

        certificateManagerService.renewCertificate();

        verify(vaultSecretProvider, never()).persistCertificate(any());
    }

    @Test
    void renewCertificate_skipsPersistenceOnVerificationFailure() {
        CreateKeyResponseDTO keyPair = CreateKeyResponseDTO.builder()
                .publicKeyPem("pub")
                .privateKeyPem("priv")
                .build();
        CreateCsrResponseDTO csr = new CreateCsrResponseDTO("id", "csr-pem");
        SignCertResponseDTO signed =
                SignCertResponseDTO.builder().certificate("cert-pem").build();

        when(pkiService.createKeyPair(null, 2048)).thenReturn(keyPair);
        when(pkiService.createCsr(any())).thenReturn(csr);
        when(managementNodeService.signCertificate(any())).thenReturn(signed);
        when(vaultSecretProvider.getIntermediateCa()).thenReturn("intermediate-pem");

        certificateManagerService.renewCertificate();

        verify(vaultSecretProvider, never()).persistCertificate(any());
    }

    @Test
    void persistSignedArtifacts_skipsVerificationIfIntermediateMissing() {
        CreateKeyResponseDTO keyPair = CreateKeyResponseDTO.builder()
                .publicKeyPem("pub")
                .privateKeyPem("priv")
                .build();
        CreateCsrResponseDTO csr = new CreateCsrResponseDTO("id", "csr-pem");
        SignCertResponseDTO signed =
                SignCertResponseDTO.builder().certificate("cert-pem").build();

        when(pkiService.createKeyPair(null, 2048)).thenReturn(keyPair);
        when(pkiService.createCsr(any())).thenReturn(csr);
        when(managementNodeService.signCertificate(any())).thenReturn(signed);
        when(vaultSecretProvider.getIntermediateCa()).thenReturn(null);

        certificateManagerService.renewCertificate();

        verify(vaultSecretProvider, times(1)).persistCertificate("cert-pem");
    }

    @Test
    void persistSignedArtifacts_guardsAgainstNulls() {
        CreateKeyResponseDTO keyPair = CreateKeyResponseDTO.builder()
                .publicKeyPem("pub")
                .privateKeyPem("priv")
                .build();
        CreateCsrResponseDTO csr = new CreateCsrResponseDTO("id", "csr-pem");
        SignCertResponseDTO signed = SignCertResponseDTO.builder()
                .certificate("cert-pem")
                .caChain(null)
                .issuingCa(null)
                .build();

        when(pkiService.createKeyPair(null, 2048)).thenReturn(keyPair);
        when(pkiService.createCsr(any())).thenReturn(csr);
        when(managementNodeService.signCertificate(any())).thenReturn(signed);
        when(vaultSecretProvider.getIntermediateCa()).thenReturn(null);

        certificateManagerService.renewCertificate();

        verify(vaultSecretProvider, times(1)).persistCertificate("cert-pem");
        verify(vaultSecretProvider, never()).persistCaChain(any());
        verify(vaultSecretProvider, never()).persistIntermediateCa(any());
    }

    @Test
    void renewCertificate_throwsExceptionOnPkiFailure() {
        when(pkiService.createKeyPair(null, 2048)).thenThrow(new PkiException("PKI failure"));

        assertThrows(PkiException.class, () -> certificateManagerService.renewCertificate());

        verify(pkiService, times(1)).createKeyPair(null, 2048);
        verify(vaultSecretProvider, never()).persistKeyPair(any());
    }

    @Test
    void checkAndRefreshIntermediateCa_persistsNewIfMissing() {
        when(vaultSecretProvider.getIntermediateCa()).thenReturn(null);
        when(managementNodeService.getIntermediateCertificate())
                .thenReturn(
                        CertificateResponseDTO.builder().certificate("new-cert").build());

        certificateManagerService.run();

        verify(vaultSecretProvider).persistIntermediateCa("new-cert");
    }

    @Test
    void checkAndRefreshIntermediateCa_guardsAgainstNullResponse() {
        when(vaultSecretProvider.getIntermediateCa()).thenReturn(null);
        when(managementNodeService.getIntermediateCertificate()).thenReturn(null);

        certificateManagerService.run();

        verify(vaultSecretProvider, never()).persistIntermediateCa(any());
    }

    @Test
    void checkAndRefreshIntermediateCa_refreshesIfExpiringSoon() throws Exception {
        // Create a cert that expires very soon
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        KeyPair kp = kpg.generateKeyPair();
        X500Name name = new X500Name("CN=Old");
        long now = System.currentTimeMillis();
        Date start = new Date(now - 100000);
        Date end = new Date(now + 1000); // Expires in 1 second
        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA").build(kp.getPrivate());
        X509v3CertificateBuilder builder =
                new JcaX509v3CertificateBuilder(name, BigInteger.valueOf(now), start, end, name, kp.getPublic());
        X509Certificate oldCert = new JcaX509CertificateConverter().getCertificate(builder.build(signer));
        String oldPem = PemUtil.toPem("CERTIFICATE", oldCert.getEncoded());

        certificateProperties.setIntermediateMinValidDays(14);

        when(vaultSecretProvider.getIntermediateCa()).thenReturn(oldPem);
        when(managementNodeService.getIntermediateCertificate())
                .thenReturn(CertificateResponseDTO.builder()
                        .certificate("fresh-cert")
                        .build());

        certificateManagerService.run();

        verify(vaultSecretProvider).persistIntermediateCa("fresh-cert");
    }

    @Test
    void run_skipsRenewalIfCertificateIsValid() throws Exception {
        // Create a cert that is valid for a long time
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        KeyPair kp = kpg.generateKeyPair();
        X500Name name = new X500Name("CN=Valid");
        long now = System.currentTimeMillis();
        Date start = new Date(now - 3600000 * 24);
        Date end = new Date(now + 3600000 * 24 * 59);
        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA").build(kp.getPrivate());
        X509v3CertificateBuilder builder =
                new JcaX509v3CertificateBuilder(name, BigInteger.valueOf(now), start, end, name, kp.getPublic());
        X509Certificate validCert = new JcaX509CertificateConverter().getCertificate(builder.build(signer));
        String validPem = PemUtil.toPem("CERTIFICATE", validCert.getEncoded());

        X509Certificate intermediateCert = new JcaX509CertificateConverter().getCertificate(builder.build(signer));
        String intermediatePem = PemUtil.toPem("CERTIFICATE", intermediateCert.getEncoded());

        when(vaultSecretProvider.getIntermediateCa()).thenReturn(intermediatePem);
        when(vaultSecretProvider.getCertificate()).thenReturn(validPem);

        certificateManagerService.run();

        verify(pkiService, never()).createKeyPair(any(), any());
    }

    @Test
    void run_renewsWhenCertificateBelowThreshold() throws Exception {
        // Create a cert that is near expiry (below 10% remaining)
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        KeyPair kp = kpg.generateKeyPair();
        X500Name name = new X500Name("CN=NearExpiry");
        long now = System.currentTimeMillis();
        // Total: 100 days. Elapsed: 95 days. Remaining: 5 days (~5% remaining < 10% threshold)
        Date start = new Date(now - 3600000L * 24 * 95);
        Date end = new Date(now + 3600000L * 24 * 5);
        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA").build(kp.getPrivate());
        X509v3CertificateBuilder builder =
                new JcaX509v3CertificateBuilder(name, BigInteger.valueOf(now), start, end, name, kp.getPublic());
        X509Certificate nearExpiryCert = new JcaX509CertificateConverter().getCertificate(builder.build(signer));
        String nearExpiryPem = PemUtil.toPem("CERTIFICATE", nearExpiryCert.getEncoded());

        // Create valid intermediate
        Date intStart = new Date(now - 3600000L * 24);
        Date intEnd = new Date(now + 3600000L * 24 * 365);
        X509v3CertificateBuilder intBuilder = new JcaX509v3CertificateBuilder(
                name, BigInteger.valueOf(now + 1), intStart, intEnd, name, kp.getPublic());
        X509Certificate intCert = new JcaX509CertificateConverter().getCertificate(intBuilder.build(signer));
        String intPem = PemUtil.toPem("CERTIFICATE", intCert.getEncoded());

        when(vaultSecretProvider.getIntermediateCa()).thenReturn(intPem);
        when(vaultSecretProvider.getCertificate()).thenReturn(nearExpiryPem);
        when(pkiService.createKeyPair(null, 2048)).thenReturn(null);

        certificateManagerService.run();

        verify(pkiService, times(1)).createKeyPair(null, 2048);
    }

    @Test
    void run_renewsIfCertificateIsMissing() {
        when(vaultSecretProvider.getIntermediateCa()).thenReturn("some-intermediate");
        when(vaultSecretProvider.getCertificate()).thenReturn(null);
        when(pkiService.createKeyPair(null, 2048))
                .thenReturn(CreateKeyResponseDTO.builder().build());

        certificateManagerService.run();

        verify(pkiService, times(1)).createKeyPair(any(), any());
    }

    @Test
    void sync_success() {
        certificateManagerService.sync();
        verify(keyStoreSyncService, times(1)).syncKeyStoresToFilesystem();
    }

    @Test
    void sync_propagatesException() {
        doThrow(new RuntimeException("sync failed")).when(keyStoreSyncService).syncKeyStoresToFilesystem();

        assertThrows(RuntimeException.class, () -> certificateManagerService.sync());
    }

    @Test
    void run_renewsIfCertificateIsBlank() {
        when(vaultSecretProvider.getIntermediateCa()).thenReturn("some-intermediate");
        when(vaultSecretProvider.getCertificate()).thenReturn("   ");
        when(pkiService.createKeyPair(null, 2048))
                .thenReturn(CreateKeyResponseDTO.builder().build());

        certificateManagerService.run();

        verify(pkiService, times(1)).createKeyPair(any(), any());
    }

    @Test
    void renewCertificate_persistsIssuingCaAndCaChain() {
        CreateKeyResponseDTO keyPair = CreateKeyResponseDTO.builder()
                .publicKeyPem("pub")
                .privateKeyPem("priv")
                .build();
        CreateCsrResponseDTO csr = new CreateCsrResponseDTO("id", "csr-pem");
        SignCertResponseDTO signed = SignCertResponseDTO.builder()
                .certificate("cert-pem")
                .issuingCa("issuing-ca-pem")
                .caChain(List.of("ca1", "ca2"))
                .build();

        when(pkiService.createKeyPair(null, 2048)).thenReturn(keyPair);
        when(pkiService.createCsr(any())).thenReturn(csr);
        when(managementNodeService.signCertificate(any())).thenReturn(signed);
        when(vaultSecretProvider.getIntermediateCa()).thenReturn(null);

        certificateManagerService.renewCertificate();

        verify(vaultSecretProvider, times(1)).persistCertificate("cert-pem");
        verify(vaultSecretProvider, times(1)).persistIntermediateCa("issuing-ca-pem");
        verify(vaultSecretProvider, times(1)).persistCaChain(List.of("ca1", "ca2"));
    }

    @Test
    void renewCertificate_withAltNamesConfigured() {
        certificateProperties.getSubject().setAltNames("api.example.com, www.example.com, , ");

        CreateKeyResponseDTO keyPair = CreateKeyResponseDTO.builder()
                .publicKeyPem("pub")
                .privateKeyPem("priv")
                .build();
        CreateCsrResponseDTO csr = new CreateCsrResponseDTO("id", "csr-pem");
        SignCertResponseDTO signed =
                SignCertResponseDTO.builder().certificate("cert-pem").build();

        when(pkiService.createKeyPair(null, 2048)).thenReturn(keyPair);
        when(pkiService.createCsr(any())).thenReturn(csr);
        when(managementNodeService.signCertificate(any())).thenReturn(signed);
        when(vaultSecretProvider.getIntermediateCa()).thenReturn(null);

        certificateManagerService.renewCertificate();

        verify(pkiService, times(1)).createCsr(any());
    }

    @Test
    void renewCertificate_skipsWhenCsrPemIsNull() {
        CreateKeyResponseDTO keyPair = CreateKeyResponseDTO.builder()
                .publicKeyPem("pub")
                .privateKeyPem("priv")
                .build();
        CreateCsrResponseDTO csr = new CreateCsrResponseDTO("id", null);
        when(pkiService.createKeyPair(null, 2048)).thenReturn(keyPair);
        when(pkiService.createCsr(any())).thenReturn(csr);

        certificateManagerService.renewCertificate();

        verify(managementNodeService, never()).signCertificate(any());
    }

    @Test
    void isBootstrapCertificate_returnsTrueWhenOidPresent() throws Exception {
        String pem = createCertWithOtherNameSan("1.3.6.1.4.1.32473.1.1", "bootstrap");
        assertTrue(certificateManagerService.isBootstrapCertificate(pem));
    }

    @Test
    void isBootstrapCertificate_returnsFalseWhenNoOid() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        KeyPair kp = kpg.generateKeyPair();
        X500Name name = new X500Name("CN=Normal");
        long now = System.currentTimeMillis();
        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA").build(kp.getPrivate());
        X509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                name, BigInteger.valueOf(now), new Date(now), new Date(now + 3600000L * 24 * 30), name, kp.getPublic());
        X509Certificate cert = new JcaX509CertificateConverter().getCertificate(builder.build(signer));
        String pem = PemUtil.toPem("CERTIFICATE", cert.getEncoded());

        assertFalse(certificateManagerService.isBootstrapCertificate(pem));
    }

    @Test
    void run_renewsImmediatelyWhenBootstrapOidDetected() throws Exception {
        String bootstrapPem = createCertWithOtherNameSan("1.3.6.1.4.1.32473.1.1", "bootstrap");

        // Valid intermediate so checkAndRefreshIntermediateCa passes
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        KeyPair kp = kpg.generateKeyPair();
        X500Name name = new X500Name("CN=Intermediate");
        long now = System.currentTimeMillis();
        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA").build(kp.getPrivate());
        X509v3CertificateBuilder intBuilder = new JcaX509v3CertificateBuilder(
                name,
                BigInteger.valueOf(now),
                new Date(now - 3600000L),
                new Date(now + 3600000L * 24 * 365),
                name,
                kp.getPublic());
        String intPem = PemUtil.toPem(
                "CERTIFICATE",
                new JcaX509CertificateConverter()
                        .getCertificate(intBuilder.build(signer))
                        .getEncoded());

        when(vaultSecretProvider.getIntermediateCa()).thenReturn(intPem);
        when(vaultSecretProvider.getCertificate()).thenReturn(bootstrapPem);
        when(pkiService.createKeyPair(null, 2048)).thenReturn(null);

        certificateManagerService.run();

        // Should trigger renewal despite cert being valid
        verify(pkiService, times(1)).createKeyPair(null, 2048);
    }

    private String createCertWithOtherNameSan(String oid, String value) throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        KeyPair kp = kpg.generateKeyPair();
        X500Name name = new X500Name("CN=Bootstrap");
        long now = System.currentTimeMillis();
        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA").build(kp.getPrivate());

        DERSequence otherNameSeq = new DERSequence(new ASN1Encodable[] {
            new ASN1ObjectIdentifier(oid), new DERTaggedObject(true, 0, new DERUTF8String(value))
        });
        GeneralName otherName = new GeneralName(GeneralName.otherName, otherNameSeq);
        GeneralNames sans = new GeneralNames(otherName);

        X509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                name, BigInteger.valueOf(now), new Date(now), new Date(now + 3600000L * 24 * 30), name, kp.getPublic());
        builder.addExtension(Extension.subjectAlternativeName, false, sans);

        X509Certificate cert = new JcaX509CertificateConverter().getCertificate(builder.build(signer));
        return PemUtil.toPem("CERTIFICATE", cert.getEncoded());
    }

    @Test
    void checkAndRefreshIntermediateCa_handlesResponseWithNullCertificate() {
        when(vaultSecretProvider.getIntermediateCa()).thenReturn(null);
        CertificateResponseDTO response =
                CertificateResponseDTO.builder().certificate(null).build();
        when(managementNodeService.getIntermediateCertificate()).thenReturn(response);

        certificateManagerService.run();

        verify(vaultSecretProvider, never()).persistIntermediateCa(any());
    }

    @Test
    void checkAndRefreshIntermediateCa_handlesResponseWithBlankCertificate() {
        when(vaultSecretProvider.getIntermediateCa()).thenReturn(null);
        CertificateResponseDTO response =
                CertificateResponseDTO.builder().certificate("   ").build();
        when(managementNodeService.getIntermediateCertificate()).thenReturn(response);

        certificateManagerService.run();

        verify(vaultSecretProvider, never()).persistIntermediateCa(any());
    }
}
