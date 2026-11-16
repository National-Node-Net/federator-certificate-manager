/*
 * SPDX-License-Identifier: Apache-2.0
 * © Crown Copyright 2026. This work has been developed by the National Digital Twin Programme and is legally
 * attributed to the UK's Department for Business, Innovation, Science and Trade (BIST) as the governing entity.
 */

package uk.gov.dbt.ndtp.federator.certificate.manager.service.pki.cryptography;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.security.cert.X509Certificate;
import java.util.List;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import uk.gov.dbt.ndtp.federator.certificate.manager.exception.PkiException;

class CertificateChainBuilderTest {

    private static TestPkiHierarchy pki;
    private static X509Certificate leaf;
    private static X509Certificate intermediate;
    private static X509Certificate root;

    @BeforeAll
    static void createPki() {
        pki = new TestPkiHierarchy();
        leaf = pki.leaf.certificate();
        intermediate = pki.intermediate.certificate();
        root = pki.root.certificate();
    }

    @ParameterizedTest
    @NullAndEmptySource
    void build_withoutCaChain_returnsLeafOnly(List<String> caChain) {
        assertEquals(List.of(leaf), CertificateChainBuilder.build(pki.leaf.pem(), caChain));
    }

    @Test
    void build_withSingleIssuer_returnsLeafAndIssuer() {
        List<X509Certificate> chain = CertificateChainBuilder.build(pki.leaf.pem(), List.of(pki.intermediate.pem()));

        assertEquals(List.of(leaf, intermediate), chain);
    }

    @Test
    void build_withOrderedChain_keepsOrder() {
        List<X509Certificate> chain =
                CertificateChainBuilder.build(pki.leaf.pem(), List.of(pki.intermediate.pem(), pki.root.pem()));

        assertEquals(List.of(leaf, intermediate, root), chain);
    }

    @Test
    void build_withOutOfOrderChain_ordersFromLeafToRoot() {
        List<X509Certificate> chain =
                CertificateChainBuilder.build(pki.leaf.pem(), List.of(pki.root.pem(), pki.intermediate.pem()));

        assertEquals(List.of(leaf, intermediate, root), chain);
    }

    @Test
    void build_withUnrelatedCa_leavesItOut() {
        String otherCa = TestPkiHierarchy.selfSigned("CN=Other Federator CA").pem();

        List<X509Certificate> chain =
                CertificateChainBuilder.build(pki.leaf.pem(), List.of(otherCa, pki.root.pem(), pki.intermediate.pem()));

        assertEquals(List.of(leaf, intermediate, root), chain);
    }

    @Test
    void build_withDuplicatesAndLeafInCaChain_removesThem() {
        List<X509Certificate> chain = CertificateChainBuilder.build(
                pki.leaf.pem(),
                List.of(pki.intermediate.pem(), pki.leaf.pem(), pki.root.pem(), pki.intermediate.pem()));

        assertEquals(List.of(leaf, intermediate, root), chain);
    }

    @Test
    void build_whenLeafIssuerMissing_returnsLeafOnly() {
        assertEquals(List.of(leaf), CertificateChainBuilder.build(pki.leaf.pem(), List.of(pki.root.pem())));
    }

    @Test
    void build_whenRootMissing_endsAtIntermediate() {
        List<X509Certificate> chain = CertificateChainBuilder.build(pki.leaf.pem(), List.of(pki.intermediate.pem()));

        assertEquals(List.of(leaf, intermediate), chain);
    }

    @Test
    void build_withRekeyedCaOfSameName_picksTheCaThatSignedTheCertificate() {
        // Same subject name as the real intermediate, but a different key (e.g. during CA rotation)
        TestPkiHierarchy.Issued rekeyed = TestPkiHierarchy.issue("CN=Test Intermediate CA", pki.root);

        List<X509Certificate> chain = CertificateChainBuilder.build(
                pki.leaf.pem(), List.of(rekeyed.pem(), pki.root.pem(), pki.intermediate.pem()));

        assertEquals(List.of(leaf, intermediate, root), chain);
    }

    @Test
    void build_withSelfSignedLeaf_returnsLeafOnly() {
        TestPkiHierarchy.Issued selfSigned = TestPkiHierarchy.selfSigned("CN=Self Signed");

        List<X509Certificate> chain = CertificateChainBuilder.build(selfSigned.pem(), List.of(pki.root.pem()));

        assertEquals(List.of(selfSigned.certificate()), chain);
    }

    @Test
    void build_withSameNameButSignedByAnotherKey_isNotTreatedAsSelfSigned() {
        // Subject and issuer names are equal, but the root's key signed it (e.g. a re-keyed root cross-signed by the
        // old one), so the walk must continue to the real issuer
        TestPkiHierarchy.Issued crossSigned = TestPkiHierarchy.issue("CN=Test Root CA", pki.root);

        List<X509Certificate> chain = CertificateChainBuilder.build(crossSigned.pem(), List.of(pki.root.pem()));

        assertEquals(List.of(crossSigned.certificate(), root), chain);
    }

    @Test
    void build_withInvalidCaPem_throwsPkiException() {
        List<String> caChain = List.of("not a certificate");
        String leafPem = pki.leaf.pem();

        assertThrows(PkiException.class, () -> CertificateChainBuilder.build(leafPem, caChain));
    }
}
