/*
 * SPDX-License-Identifier: Apache-2.0
 * © Crown Copyright 2026. This work has been developed by the National Digital Twin Programme and is legally
 * attributed to the UK's Department for Business, Innovation, Science and Trade (BIST) as the governing entity.
 */

package uk.gov.dbt.ndtp.federator.certificate.manager.exception;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.net.ConnectException;
import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.HttpServerErrorException;
import org.springframework.web.client.ResourceAccessException;

class ExternalCallErrorsTest {

    @Test
    void describe_null_returnsUnknown() {
        assertEquals("unknown error", ExternalCallErrors.describe(null));
    }

    @Test
    void describe_httpErrorWrappedInDomainException_showsStatusAndBody() {
        HttpClientErrorException forbidden = HttpClientErrorException.create(
                HttpStatus.FORBIDDEN,
                "",
                HttpHeaders.EMPTY,
                "{\"message\":\"Access denied\",\n \"errorId\":\"abc\"}".getBytes(StandardCharsets.UTF_8),
                StandardCharsets.UTF_8);
        ManagementNodeException wrapped = new ManagementNodeException("failed", forbidden);

        assertEquals(
                "HTTP 403 Forbidden - {\"message\":\"Access denied\", \"errorId\":\"abc\"}",
                ExternalCallErrors.describe(wrapped));
    }

    @Test
    void describe_httpErrorWithoutBody_showsStatusOnly() {
        HttpServerErrorException error = HttpServerErrorException.create(
                HttpStatus.BAD_GATEWAY, "Bad Gateway", HttpHeaders.EMPTY, new byte[0], StandardCharsets.UTF_8);

        assertEquals("HTTP 502 Bad Gateway", ExternalCallErrors.describe(error));
    }

    @Test
    void describe_longBody_isTruncated() {
        String body = "x".repeat(ExternalCallErrors.MAX_BODY_LENGTH + 100);
        HttpServerErrorException error = HttpServerErrorException.create(
                HttpStatus.INTERNAL_SERVER_ERROR,
                "Internal Server Error",
                HttpHeaders.EMPTY,
                body.getBytes(StandardCharsets.UTF_8),
                StandardCharsets.UTF_8);

        String description = ExternalCallErrors.describe(error);

        assertTrue(description.endsWith("...(truncated)"), description);
        assertTrue(description.length() < body.length(), description);
    }

    @Test
    void describe_connectionFailure_showsRootCause() {
        ResourceAccessException error = new ResourceAccessException(
                "I/O error on GET request", new ConnectException("Connect to https://localhost:8090 failed"));

        assertEquals(
                "ConnectException: Connect to https://localhost:8090 failed",
                ExternalCallErrors.describe(new OAuth2TokenException("token failed", error)));
    }

    @Test
    void describe_exceptionWithoutMessage_showsClassName() {
        assertEquals("IllegalStateException", ExternalCallErrors.describe(new IllegalStateException()));
    }

    @Test
    void rootCause_returnsDeepestCause() {
        IllegalArgumentException root = new IllegalArgumentException("root");
        RuntimeException top = new RuntimeException("top", new IllegalStateException("middle", root));

        assertSame(root, ExternalCallErrors.rootCause(top));
        assertSame(root, ExternalCallErrors.rootCause(root));
    }
}
