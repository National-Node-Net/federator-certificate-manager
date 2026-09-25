/*
 * SPDX-License-Identifier: Apache-2.0
 * © Crown Copyright 2026. This work has been developed by the National Digital Twin Programme and is legally
 * attributed to the UK's Department for Business, Innovation, Science and Trade (BIST) as the governing entity.
 */

package uk.gov.dbt.ndtp.federator.certificate.manager.service.pki;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import uk.gov.dbt.ndtp.federator.certificate.manager.exception.KeyStoreCreationException;
import uk.gov.dbt.ndtp.federator.certificate.manager.exception.PkiException;
import uk.gov.dbt.ndtp.federator.certificate.manager.service.pki.cryptography.PemUtil;

@Slf4j
@Service
public class KeyStoreService {

    /**
     * Creates a PKCS12 keystore containing a private key and its certificate chain.
     *
     * @param privateKeyPem the private key in PEM format
     * @param certificatePem the leaf certificate in PEM format
     * @param caChain the list of CA certificates in PEM format
     * @param password the password for the keystore
     * @param alias the alias for the key entry
     * @return the serialized PKCS12 keystore as a byte array
     * @throws Exception if keystore creation or serialization fails
     */
    public byte[] createKeyStore(
            String privateKeyPem, String certificatePem, List<String> caChain, String password, String alias) {
        try {
            PrivateKey privateKey = PemUtil.parsePkcs8PrivateKey(privateKeyPem);
            X509Certificate cert = PemUtil.parseCertificate(certificatePem);

            List<Certificate> chain = new ArrayList<>();
            chain.add(cert);
            if (caChain != null) {
                for (String caPem : caChain) {
                    chain.add(PemUtil.parseCertificate(caPem));
                }
            }

            KeyStore ks = KeyStore.getInstance("PKCS12");
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
     *
     * @param caChain the list of CA certificates in PEM format
     * @param password the password for the truststore
     * @return the serialized PKCS12 truststore as a byte array
     * @throws Exception if truststore creation or serialization fails
     */
    public byte[] createTrustStore(List<String> caChain, String password, Path existingTrustStore) {
        try {
            KeyStore ks = KeyStore.getInstance("PKCS12");
            if (Files.exists(existingTrustStore)) {
                try (InputStream in = Files.newInputStream(existingTrustStore)) {
                    ks.load(in, password.toCharArray());
                }
            } else {
                ks.load(null, null);
            }

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
}
