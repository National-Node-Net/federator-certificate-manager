/*
 * SPDX-License-Identifier: Apache-2.0
 * © Crown Copyright 2026. This work has been developed by the National Digital Twin Programme and is legally
 * attributed to the UK's Department for Business, Innovation, Science and Trade (BIST) as the governing entity.
 */

package uk.gov.dbt.ndtp.federator.certificate.manager.util;

import org.springframework.http.HttpStatus;
import org.springframework.web.client.RestClientResponseException;

/**
 * Turns failures from calls to external services (Management Node, Keycloak, Vault) into a single, readable line,
 * so the reason for a failure (HTTP status and response body, connection refused, TLS failure, ...) is visible in
 * the log message itself instead of being buried at the bottom of a long stack trace.
 */
public final class ExternalCallErrors {

    static final int MAX_BODY_LENGTH = 500;

    /**
     * Limit on how far a cause chain is followed. {@link Throwable#getCause()} never returns the throwable itself, but
     * a longer cycle (A caused by B caused by A) is possible, so the walk stops here.
     */
    private static final int MAX_CAUSE_DEPTH = 50;

    private ExternalCallErrors() {}

    /**
     * Describes the reason for a failure.
     * <ul>
     *     <li>HTTP error responses: {@code HTTP 403 Forbidden - <response body>}</li>
     *     <li>anything else: {@code <RootCauseClass>: <root cause message>}, e.g.
     *     {@code HttpHostConnectException: Connect to https://localhost:8090 failed: Connection refused}</li>
     * </ul>
     *
     * @param throwable the failure
     * @return a one-line description of the failure
     */
    public static String describe(Throwable throwable) {
        if (throwable == null) {
            return "unknown error";
        }
        RestClientResponseException httpError = findCause(throwable, RestClientResponseException.class);
        if (httpError != null) {
            return describeHttpError(httpError);
        }
        Throwable root = rootCause(throwable);
        String message = root.getMessage();
        return root.getClass().getSimpleName() + (message == null || message.isBlank() ? "" : ": " + oneLine(message));
    }

    /**
     * Returns the deepest cause in the chain of the given throwable (guarding against cycles).
     *
     * @param throwable the failure
     * @return the root cause, or the throwable itself if it has no cause
     */
    public static Throwable rootCause(Throwable throwable) {
        Throwable current = throwable;
        int depth = 0;
        while (current.getCause() != null && depth++ < MAX_CAUSE_DEPTH) {
            current = current.getCause();
        }
        return current;
    }

    private static String describeHttpError(RestClientResponseException httpError) {
        int status = httpError.getStatusCode().value();
        String reason = httpError.getStatusText();
        if (reason == null || reason.isBlank()) {
            HttpStatus resolved = HttpStatus.resolve(status);
            reason = resolved != null ? resolved.getReasonPhrase() : "";
        }
        StringBuilder description = new StringBuilder("HTTP ").append(status);
        if (!reason.isBlank()) {
            description.append(' ').append(reason);
        }
        String body = httpError.getResponseBodyAsString();
        if (!body.isBlank()) {
            description.append(" - ").append(truncate(oneLine(body)));
        }
        return description.toString();
    }

    private static <T extends Throwable> T findCause(Throwable throwable, Class<T> type) {
        Throwable current = throwable;
        int depth = 0;
        while (current != null && depth++ < MAX_CAUSE_DEPTH) {
            if (type.isInstance(current)) {
                return type.cast(current);
            }
            current = current.getCause();
        }
        return null;
    }

    private static String oneLine(String value) {
        return value.replaceAll("\\s*[\\r\\n]+\\s*", " ").strip();
    }

    private static String truncate(String value) {
        return value.length() <= MAX_BODY_LENGTH ? value : value.substring(0, MAX_BODY_LENGTH) + "...(truncated)";
    }
}
