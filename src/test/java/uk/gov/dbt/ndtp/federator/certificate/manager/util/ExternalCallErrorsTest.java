/*
 * SPDX-License-Identifier: Apache-2.0
 * © Crown Copyright 2026. This work has been developed by the National Digital Twin Programme and is legally
 * attributed to the UK's Department for Business, Innovation, Science and Trade (BIST) as the governing entity.
 */

package uk.gov.dbt.ndtp.federator.certificate.manager.util;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTimeoutPreemptively;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.net.ConnectException;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.HttpServerErrorException;
import org.springframework.web.client.ResourceAccessException;
import org.springframework.web.client.RestClientResponseException;
import uk.gov.dbt.ndtp.federator.certificate.manager.exception.ManagementNodeException;
import uk.gov.dbt.ndtp.federator.certificate.manager.exception.OAuth2TokenException;

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

    @Test
    void describe_httpErrorWithoutReasonPhrase_usesStandardReasonForStatus() {
        RestClientResponseException error =
                new RestClientResponseException("failed", HttpStatus.NOT_FOUND, "", null, null, null);

        assertEquals("HTTP 404 Not Found", ExternalCallErrors.describe(error));
    }

    @Test
    void describe_httpErrorWithNullReasonPhrase_usesStandardReasonForStatus() {
        RestClientResponseException error =
                new RestClientResponseException("failed", HttpStatus.UNAUTHORIZED, null, null, null, null);

        assertEquals("HTTP 401 Unauthorized", ExternalCallErrors.describe(error));
    }

    @Test
    void describe_httpErrorWithNonStandardStatus_showsStatusCodeOnly() {
        RestClientResponseException error = new RestClientResponseException("failed", 599, "", null, null, null);

        assertEquals("HTTP 599", ExternalCallErrors.describe(error));
    }

    @Test
    void describe_exceptionWithBlankMessage_showsClassName() {
        assertEquals("IllegalStateException", ExternalCallErrors.describe(new IllegalStateException("  ")));
    }

    @Test
    void describe_multiLineMessage_isJoinedOnOneLine() {
        assertEquals(
                "IllegalStateException: first line second line",
                ExternalCallErrors.describe(new IllegalStateException("first line\n   second line\n")));
    }

    @Test
    void describe_causeCycle_terminates() {
        IllegalStateException first = new IllegalStateException("first");
        IllegalArgumentException second = new IllegalArgumentException("second");
        first.initCause(second);
        second.initCause(first);

        String description = assertTimeoutPreemptively(Duration.ofSeconds(5), () -> ExternalCallErrors.describe(first));

        assertNotNull(description);
    }
}
