/*
 * SPDX-License-Identifier: Apache-2.0
 * © Crown Copyright 2026. This work has been developed by the National Digital Twin Programme and is legally
 * attributed to the UK's Department for Business, Innovation, Science and Trade (BIST) as the governing entity.
 */

package uk.gov.dbt.ndtp.federator.certificate.manager.config;

import com.github.benmanes.caffeine.cache.Caffeine;
import java.util.concurrent.TimeUnit;
import org.springframework.cache.CacheManager;
import org.springframework.cache.annotation.EnableCaching;
import org.springframework.cache.caffeine.CaffeineCacheManager;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * Configuration class for Spring Caching.
 * Enables caching and configures Caffeine as the cache provider.
 */
@Configuration
@EnableCaching
public class CacheConfig {

    public static final String TOKEN_CACHE = "tokenCache";

    /**
     * Configures the CacheManager using Caffeine.
     * Sets up the "tokenCache" with specific eviction and size policies.
     *
     * @return the configured CacheManager
     */
    @Bean
    public CacheManager cacheManager() {
        CaffeineCacheManager cacheManager = new CaffeineCacheManager(TOKEN_CACHE);
        cacheManager.setCaffeine(
                Caffeine.newBuilder().expireAfterWrite(1, TimeUnit.HOURS).maximumSize(10));
        return cacheManager;
    }
}
