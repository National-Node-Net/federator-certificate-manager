/*
 * SPDX-License-Identifier: Apache-2.0
 * © Crown Copyright 2026. This work has been developed by the National Digital Twin Programme and is legally
 * attributed to the UK's Department for Business, Innovation, Science and Trade (BIST) as the governing entity.
 */

package uk.gov.dbt.ndtp.federator.certificate.manager.service.pki;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.List;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import uk.gov.dbt.ndtp.federator.certificate.manager.exception.KeyStoreCreationException;
import uk.gov.dbt.ndtp.federator.certificate.manager.exception.PkiException;
import uk.gov.dbt.ndtp.federator.certificate.manager.service.pki.cryptography.CertificateChainBuilder;
import uk.gov.dbt.ndtp.federator.certificate.manager.service.pki.cryptography.PemUtil;

@Slf4j
@Service
public class KeyStoreService {
    private static final String PKCS12 = "PKCS12";

    /**
     * Creates a PKCS12 keystore containing a private key and its certificate chain.
     * The chain is ordered from the leaf up through its issuers (see {@link CertificateChainBuilder}), so the CA chain
     * may be given in any order and may contain certificates that are not on the leaf's issuing path.
     *
     * @param privateKeyPem the private key in PEM format
     * @param certificatePem the leaf certificate in PEM format
     * @param caChain the list of CA certificates in PEM format, in any order
     * @param password the password for the keystore
     * @param alias the alias for the key entry
     * @return the serialized PKCS12 keystore as a byte array
     * @throws Exception if keystore creation or serialization fails
     */
    public byte[] createKeyStore(
            String privateKeyPem, String certificatePem, List<String> caChain, String password, String alias) {
        try {
            PrivateKey privateKey = PemUtil.parsePkcs8PrivateKey(privateKeyPem);
            List<X509Certificate> chain = CertificateChainBuilder.build(certificatePem, caChain);

            KeyStore ks = KeyStore.getInstance(PKCS12);
            ks.load(null, null);
            ks.setKeyEntry(alias, privateKey, password.toCharArray(), chain.toArray(new Certificate[0]));

            return storeKeyStore(ks, password);
        } catch (PkiException e) {
            throw e;
        } catch (Exception e) {
            throw new KeyStoreCreationException("Failed to create keystore ", e);
        }
    }

    private byte[] storeKeyStore(KeyStore ks, String password) {
        try (ByteArrayOutputStream bos = new ByteArrayOutputStream()) {
            ks.store(bos, password.toCharArray());
            return bos.toByteArray();
        } catch (Exception e) {
            throw new PkiException("Failed to serialize keystore", e);
        }
    }

    /**
     * Creates a PKCS12 truststore containing a list of CA certificates.
     * Entries from an existing truststore are kept when it can be opened with the given password;
     * otherwise (e.g. the password changed or the file is corrupt) a fresh truststore is created.
     *
     * @param caChain the list of CA certificates in PEM format
     * @param password the password for the truststore
     * @param existingTrustStore path of a previously written truststore to merge into, if present
     * @return the serialized PKCS12 truststore as a byte array
     * @throws Exception if truststore creation or serialization fails
     */
    public byte[] createTrustStore(List<String> caChain, String password, Path existingTrustStore) {
        try {
            KeyStore ks = loadExistingOrEmptyTrustStore(existingTrustStore, password);

            if (caChain != null) {
                for (int i = 0; i < caChain.size(); i++) {
                    X509Certificate caCert = PemUtil.parseCertificate(caChain.get(i));
                    ks.setCertificateEntry("ca-" + i, caCert);
                }
            }

            return storeKeyStore(ks, password);
        } catch (PkiException e) {
            throw e;
        } catch (Exception e) {
            throw new PkiException("Failed to create truststore", e);
        }
    }

    private KeyStore loadExistingOrEmptyTrustStore(Path existingTrustStore, String password)
            throws GeneralSecurityException, IOException {
        if (existingTrustStore != null && Files.exists(existingTrustStore)) {
            KeyStore existing = KeyStore.getInstance(PKCS12);
            try (InputStream in = Files.newInputStream(existingTrustStore)) {
                existing.load(in, password.toCharArray());
                return existing;
            } catch (IOException | GeneralSecurityException e) {
                log.warn(
                        "Existing truststore {} could not be opened ({}). Creating a new truststore instead.",
                        existingTrustStore,
                        e.getMessage());
            }
        }
        KeyStore ks = KeyStore.getInstance(PKCS12);
        ks.load(null, null);
        return ks;
    }
}
