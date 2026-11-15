/*
 * SPDX-License-Identifier: Apache-2.0
 * © Crown Copyright 2026. This work has been developed by the National Digital Twin Programme and is legally
 * attributed to the UK's Department for Business, Innovation, Science and Trade (BIST) as the governing entity.
 */

package uk.gov.dbt.ndtp.federator.certificate.manager.config;

import io.github.resilience4j.circuitbreaker.CircuitBreaker;
import io.github.resilience4j.core.registry.EntryAddedEvent;
import io.github.resilience4j.core.registry.EntryRemovedEvent;
import io.github.resilience4j.core.registry.EntryReplacedEvent;
import io.github.resilience4j.core.registry.RegistryEventConsumer;
import io.github.resilience4j.retry.Retry;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import uk.gov.dbt.ndtp.federator.certificate.manager.exception.ExternalCallErrors;

/**
 * Logs what the retries and circuit breakers protecting the Management Node, Keycloak and Vault actually do: each
 * retry attempt and its reason, retries being used up, recovery after a retry, and circuit breaker state changes or
 * rejected calls. Without this, a failing call is retried silently and an open circuit breaker only shows up as a
 * {@code CallNotPermittedException}.
 */
@Slf4j
@Configuration
public class ResilienceEventLoggingConfig {

    /**
     * Attaches logging to every retry instance as it is created.
     *
     * @return a registry consumer which logs retry events
     */
    @Bean
    public RegistryEventConsumer<Retry> retryEventLogger() {
        return new RegistryEventConsumer<>() {
            @Override
            public void onEntryAddedEvent(EntryAddedEvent<Retry> event) {
                registerRetryLogging(event.getAddedEntry());
            }

            @Override
            public void onEntryRemovedEvent(EntryRemovedEvent<Retry> event) {
                // nothing to clean up
            }

            @Override
            public void onEntryReplacedEvent(EntryReplacedEvent<Retry> event) {
                registerRetryLogging(event.getNewEntry());
            }
        };
    }

    /**
     * Attaches logging to every circuit breaker instance as it is created.
     *
     * @return a registry consumer which logs circuit breaker events
     */
    @Bean
    public RegistryEventConsumer<CircuitBreaker> circuitBreakerEventLogger() {
        return new RegistryEventConsumer<>() {
            @Override
            public void onEntryAddedEvent(EntryAddedEvent<CircuitBreaker> event) {
                registerCircuitBreakerLogging(event.getAddedEntry());
            }

            @Override
            public void onEntryRemovedEvent(EntryRemovedEvent<CircuitBreaker> event) {
                // nothing to clean up
            }

            @Override
            public void onEntryReplacedEvent(EntryReplacedEvent<CircuitBreaker> event) {
                registerCircuitBreakerLogging(event.getNewEntry());
            }
        };
    }

    static void registerRetryLogging(Retry retry) {
        int maxAttempts = retry.getRetryConfig().getMaxAttempts();
        retry.getEventPublisher()
                .onRetry(e -> log.warn(
                        "[retry:{}] Attempt {}/{} failed: {}. Retrying in {} ms.",
                        e.getName(),
                        e.getNumberOfRetryAttempts(),
                        maxAttempts,
                        ExternalCallErrors.describe(e.getLastThrowable()),
                        e.getWaitInterval().toMillis()))
                .onError(e -> log.error(
                        "[retry:{}] Giving up after {} attempt(s): {}",
                        e.getName(),
                        e.getNumberOfRetryAttempts(),
                        ExternalCallErrors.describe(e.getLastThrowable())))
                .onSuccess(e -> log.info(
                        "[retry:{}] Call succeeded after {} retry attempt(s).",
                        e.getName(),
                        e.getNumberOfRetryAttempts()))
                .onIgnoredError(e -> log.debug(
                        "[retry:{}] Not retrying {} (not a retryable exception).",
                        e.getName(),
                        ExternalCallErrors.describe(e.getLastThrowable())));
    }

    static void registerCircuitBreakerLogging(CircuitBreaker circuitBreaker) {
        circuitBreaker
                .getEventPublisher()
                .onStateTransition(e -> log.warn(
                        "[circuit-breaker:{}] State changed {} -> {}",
                        e.getCircuitBreakerName(),
                        e.getStateTransition().getFromState(),
                        e.getStateTransition().getToState()))
                .onFailureRateExceeded(e -> log.error(
                        "[circuit-breaker:{}] Failure rate {}% exceeded the configured threshold.",
                        e.getCircuitBreakerName(), e.getFailureRate()))
                .onCallNotPermitted(e -> log.error(
                        "[circuit-breaker:{}] Call rejected without contacting the service because the circuit"
                                + " breaker is {} after repeated failures. Check the earlier errors for the cause.",
                        e.getCircuitBreakerName(),
                        circuitBreaker.getState()));
    }
}
