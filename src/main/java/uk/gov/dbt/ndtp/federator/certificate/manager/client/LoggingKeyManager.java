/*
 * SPDX-License-Identifier: Apache-2.0
 * © Crown Copyright 2026. This work has been developed by the National Digital Twin Programme and is legally
 * attributed to the UK's Department for Business, Innovation, Science and Trade (BIST) as the governing entity.
 */

package uk.gov.dbt.ndtp.federator.certificate.manager.client;

import java.net.Socket;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import javax.net.ssl.X509ExtendedKeyManager;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Provides a log when initiating TLS session of the alias and expiry of the selected certificate.
 */
public class LoggingKeyManager extends X509ExtendedKeyManager {
    private static final Logger log = LoggerFactory.getLogger(LoggingKeyManager.class);

    private final X509ExtendedKeyManager delegate;

    public LoggingKeyManager(X509ExtendedKeyManager delegate) {
        this.delegate = delegate;
    }

    @Override
    public String chooseClientAlias(String[] keyType, Principal[] issuers, Socket socket) {

        String alias = delegate.chooseClientAlias(keyType, issuers, socket);

        if (alias != null) {
            X509Certificate[] chain = delegate.getCertificateChain(alias);

            if (chain != null && chain.length > 0) {
                X509Certificate cert = chain[0];

                log.info(
                        "TLS client certificate selected: alias={}, subject={}, expires={}",
                        alias,
                        cert.getSubjectX500Principal(),
                        cert.getNotAfter());
            }
        }

        return alias;
    }

    @Override
    public X509Certificate[] getCertificateChain(String alias) {
        return delegate.getCertificateChain(alias);
    }

    @Override
    public PrivateKey getPrivateKey(String alias) {
        return delegate.getPrivateKey(alias);
    }

    @Override
    public String[] getClientAliases(String keyType, Principal[] issuers) {
        return delegate.getClientAliases(keyType, issuers);
    }

    @Override
    public String chooseEngineClientAlias(String[] keyType, Principal[] issuers, javax.net.ssl.SSLEngine engine) {
        return delegate.chooseEngineClientAlias(keyType, issuers, engine);
    }

    @Override
    public String[] getServerAliases(String keyType, Principal[] issuers) {
        return delegate.getServerAliases(keyType, issuers);
    }

    @Override
    public String chooseServerAlias(String keyType, Principal[] issuers, Socket socket) {
        return delegate.chooseServerAlias(keyType, issuers, socket);
    }
}
