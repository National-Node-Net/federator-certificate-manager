/*
 * SPDX-License-Identifier: Apache-2.0
 * © Crown Copyright 2026. This work has been developed by the National Digital Twin Programme and is legally
 * attributed to the UK's Department for Business, Innovation, Science and Trade (BIST) as the governing entity.
 */

package uk.gov.dbt.ndtp.federator.certificate.manager.config;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import java.net.Socket;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.List;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.X509ExtendedKeyManager;
import javax.security.auth.x500.X500Principal;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;
import uk.gov.dbt.ndtp.federator.certificate.manager.client.LoggingKeyManager;

class LoggingKeyManagerTest {

    private X509ExtendedKeyManager delegate;
    private LoggingKeyManager keyManager;

    private ListAppender<ILoggingEvent> logAppender;

    @BeforeEach
    void setup() {

        delegate = mock(X509ExtendedKeyManager.class);
        keyManager = new LoggingKeyManager(delegate);

        Logger logger = (Logger) LoggerFactory.getLogger(LoggingKeyManager.class);

        logAppender = new ListAppender<>();
        logAppender.start();
        logger.addAppender(logAppender);
    }

    @Test
    void shouldLogCertificateDetailsWhenAliasSelected() {

        String alias = "client-cert";

        X509Certificate cert = mock(X509Certificate.class);

        when(cert.getSubjectX500Principal()).thenReturn(new X500Principal("CN=test"));
        when(cert.getNotAfter()).thenReturn(new java.util.Date());

        when(delegate.chooseClientAlias(any(), any(), any())).thenReturn(alias);

        when(delegate.getCertificateChain(alias)).thenReturn(new X509Certificate[] {cert});

        String result = keyManager.chooseClientAlias(new String[] {"RSA"}, new Principal[0], new Socket());

        assertEquals(alias, result);

        List<ILoggingEvent> logs = logAppender.list;

        assertEquals(1, logs.size());
        assertTrue(logs.get(0).getFormattedMessage().contains("TLS client certificate selected"));
    }

    @Test
    void shouldNotLogWhenAliasIsNull() {

        when(delegate.chooseClientAlias(any(), any(), any())).thenReturn(null);

        String result = keyManager.chooseClientAlias(new String[] {"RSA"}, null, new Socket());

        assertNull(result);
        assertTrue(logAppender.list.isEmpty());
    }

    @Test
    void shouldNotLogWhenCertificateChainIsEmpty() {

        String alias = "client-cert";

        when(delegate.chooseClientAlias(any(), any(), any())).thenReturn(alias);

        when(delegate.getCertificateChain(alias)).thenReturn(new X509Certificate[0]);

        keyManager.chooseClientAlias(new String[] {"RSA"}, null, new Socket());

        assertTrue(logAppender.list.isEmpty());
    }

    @Test
    void shouldDelegateGetPrivateKey() {

        PrivateKey key = mock(PrivateKey.class);

        when(delegate.getPrivateKey("alias")).thenReturn(key);

        assertEquals(key, keyManager.getPrivateKey("alias"));
    }

    @Test
    void shouldDelegateGetCertificateChain() {

        X509Certificate cert = mock(X509Certificate.class);

        when(delegate.getCertificateChain("alias")).thenReturn(new X509Certificate[] {cert});

        assertEquals(cert, keyManager.getCertificateChain("alias")[0]);
    }

    @Test
    void testGetClientAliases() {
        String keyType = "RSA";
        Principal[] issuers = new Principal[0];
        String[] expected = new String[] {"alias1", "alias2"};

        when(delegate.getClientAliases(keyType, issuers)).thenReturn(expected);

        String[] result = keyManager.getClientAliases(keyType, issuers);

        assertArrayEquals(expected, result);
        verify(delegate).getClientAliases(keyType, issuers);
    }

    @Test
    void testChooseEngineClientAlias() {
        String[] keyTypes = {"RSA"};
        Principal[] issuers = new Principal[0];
        SSLEngine engine = mock(SSLEngine.class);
        String expected = "alias";

        when(delegate.chooseEngineClientAlias(keyTypes, issuers, engine)).thenReturn(expected);

        String result = keyManager.chooseEngineClientAlias(keyTypes, issuers, engine);

        assertEquals(expected, result);
        verify(delegate).chooseEngineClientAlias(keyTypes, issuers, engine);
    }

    @Test
    void testGetServerAliases() {
        String keyType = "RSA";
        Principal[] issuers = new Principal[0];
        String[] expected = new String[] {"serverAlias"};

        when(delegate.getServerAliases(keyType, issuers)).thenReturn(expected);

        String[] result = keyManager.getServerAliases(keyType, issuers);

        assertArrayEquals(expected, result);
        verify(delegate).getServerAliases(keyType, issuers);
    }

    @Test
    void testChooseServerAlias() {
        String keyType = "RSA";
        Principal[] issuers = new Principal[0];
        Socket socket = mock(Socket.class);
        String expected = "serverAlias";

        when(delegate.chooseServerAlias(keyType, issuers, socket)).thenReturn(expected);

        String result = keyManager.chooseServerAlias(keyType, issuers, socket);

        assertEquals(expected, result);
        verify(delegate).chooseServerAlias(keyType, issuers, socket);
    }
}
