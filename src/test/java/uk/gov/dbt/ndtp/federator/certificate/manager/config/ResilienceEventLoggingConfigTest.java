/*
 * SPDX-License-Identifier: Apache-2.0
 * © Crown Copyright 2026. This work has been developed by the National Digital Twin Programme and is legally
 * attributed to the UK's Department for Business, Innovation, Science and Trade (BIST) as the governing entity.
 */

package uk.gov.dbt.ndtp.federator.certificate.manager.config;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import io.github.resilience4j.circuitbreaker.CallNotPermittedException;
import io.github.resilience4j.circuitbreaker.CircuitBreaker;
import io.github.resilience4j.circuitbreaker.CircuitBreakerConfig;
import io.github.resilience4j.circuitbreaker.CircuitBreakerRegistry;
import io.github.resilience4j.retry.Retry;
import io.github.resilience4j.retry.RetryConfig;
import io.github.resilience4j.retry.RetryRegistry;
import java.time.Duration;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;
import uk.gov.dbt.ndtp.federator.certificate.manager.exception.ManagementNodeException;

class ResilienceEventLoggingConfigTest {

    private final ResilienceEventLoggingConfig config = new ResilienceEventLoggingConfig();
    private ListAppender<ILoggingEvent> appender;
    private Logger logger;

    @BeforeEach
    void attachAppender() {
        logger = (Logger) LoggerFactory.getLogger(ResilienceEventLoggingConfig.class);
        appender = new ListAppender<>();
        appender.start();
        logger.addAppender(appender);
    }

    @AfterEach
    void detachAppender() {
        logger.detachAppender(appender);
    }

    private List<String> messages() {
        return appender.list.stream().map(ILoggingEvent::getFormattedMessage).toList();
    }

    @Test
    void retry_logsEachAttemptAndGivingUp() {
        RetryRegistry registry = RetryRegistry.of(
                RetryConfig.custom()
                        .maxAttempts(2)
                        .waitDuration(Duration.ofMillis(1))
                        .build(),
                config.retryEventLogger());
        Retry retry = registry.retry("management-node");

        assertThrows(
                ManagementNodeException.class,
                () -> retry.executeSupplier(() -> {
                    throw new ManagementNodeException("Failed [GET https://mn]: HTTP 403 Forbidden");
                }));

        List<String> messages = messages();
        assertTrue(
                messages.stream().anyMatch(m -> m.startsWith("[retry:management-node] Attempt 1/2 failed")),
                messages::toString);
        assertTrue(
                messages.stream().anyMatch(m -> m.startsWith("[retry:management-node] Giving up after 2 attempt(s)")),
                messages::toString);
    }

    @Test
    void retry_logsRecoveryAfterRetry() {
        RetryRegistry registry = RetryRegistry.of(
                RetryConfig.custom()
                        .maxAttempts(3)
                        .waitDuration(Duration.ofMillis(1))
                        .build(),
                config.retryEventLogger());
        Retry retry = registry.retry("oauth2");
        AtomicInteger calls = new AtomicInteger();

        String result = retry.executeSupplier(() -> {
            if (calls.incrementAndGet() == 1) {
                throw new IllegalStateException("temporary");
            }
            return "ok";
        });

        assertEquals("ok", result);
        assertTrue(
                messages().contains("[retry:oauth2] Call succeeded after 1 retry attempt(s)."), messages()::toString);
    }

    @Test
    void retry_logsIgnoredErrorAtDebug() {
        logger.setLevel(ch.qos.logback.classic.Level.DEBUG);
        RetryRegistry registry = RetryRegistry.of(
                RetryConfig.custom()
                        .maxAttempts(3)
                        .retryExceptions(ManagementNodeException.class)
                        .build(),
                config.retryEventLogger());
        Retry retry = registry.retry("vault");

        assertThrows(
                IllegalStateException.class,
                () -> retry.executeSupplier(() -> {
                    throw new IllegalStateException("bad config");
                }));

        assertTrue(messages().stream().anyMatch(m -> m.startsWith("[retry:vault] Not retrying")), messages()::toString);
    }

    @Test
    void retry_replacedEntryIsAlsoLogged() {
        RetryRegistry registry = RetryRegistry.of(RetryConfig.ofDefaults(), config.retryEventLogger());
        registry.retry("a");
        Retry newRetry = Retry.of("a", RetryConfig.custom().maxAttempts(1).build());
        registry.replace("a", newRetry);

        assertThrows(
                IllegalStateException.class,
                () -> newRetry.executeSupplier(() -> {
                    throw new IllegalStateException("boom");
                }));
        registry.remove("a");

        assertTrue(messages().stream().anyMatch(m -> m.startsWith("[retry:a] Giving up")), messages()::toString);
    }

    @Test
    void circuitBreaker_logsOpeningAndRejectedCalls() {
        CircuitBreakerRegistry registry = CircuitBreakerRegistry.of(
                CircuitBreakerConfig.custom()
                        .slidingWindowSize(2)
                        .minimumNumberOfCalls(2)
                        .failureRateThreshold(50)
                        .build(),
                config.circuitBreakerEventLogger());
        CircuitBreaker circuitBreaker = registry.circuitBreaker("management-node");

        for (int i = 0; i < 2; i++) {
            assertThrows(
                    IllegalStateException.class,
                    () -> circuitBreaker.executeSupplier(() -> {
                        throw new IllegalStateException("down");
                    }));
        }
        assertThrows(CallNotPermittedException.class, () -> circuitBreaker.executeSupplier(() -> "never"));

        List<String> messages = messages();
        assertTrue(
                messages.contains("[circuit-breaker:management-node] State changed CLOSED -> OPEN"),
                messages::toString);
        assertTrue(
                messages.stream().anyMatch(m -> m.startsWith("[circuit-breaker:management-node] Failure rate")),
                messages::toString);
        assertTrue(
                messages.stream().anyMatch(m -> m.startsWith("[circuit-breaker:management-node] Call rejected")),
                messages::toString);
    }

    @Test
    void circuitBreaker_replacedEntryIsAlsoLogged() {
        CircuitBreakerRegistry registry =
                CircuitBreakerRegistry.of(CircuitBreakerConfig.ofDefaults(), config.circuitBreakerEventLogger());
        registry.circuitBreaker("cb");
        CircuitBreaker newCb = CircuitBreaker.ofDefaults("cb");
        registry.replace("cb", newCb);

        newCb.transitionToOpenState();
        registry.remove("cb");

        assertTrue(messages().contains("[circuit-breaker:cb] State changed CLOSED -> OPEN"), messages()::toString);
    }
}
