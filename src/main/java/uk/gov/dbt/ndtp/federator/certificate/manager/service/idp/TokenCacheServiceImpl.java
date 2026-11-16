/*
 * SPDX-License-Identifier: Apache-2.0
 * © Crown Copyright 2026. This work has been developed by the National Digital Twin Programme and is legally
 * attributed to the UK's Department for Business, Innovation, Science and Trade (BIST) as the governing entity.
 */

package uk.gov.dbt.ndtp.federator.certificate.manager.service.idp;

import lombok.extern.slf4j.Slf4j;
import org.springframework.cache.Cache;
import org.springframework.cache.CacheManager;
import org.springframework.stereotype.Service;
import uk.gov.dbt.ndtp.federator.certificate.manager.config.CacheConfig;
import uk.gov.dbt.ndtp.federator.certificate.manager.exception.OAuth2TokenException;

/**
 * Service for caching and managing the lifecycle of the OAuth2 access token.
 * It provides methods to retrieve the token and automatically refreshes it before it expires.
 */
@Slf4j
@Service
public class TokenCacheServiceImpl implements TokenCacheService {

    private static final long REFRESH_BEFORE_EXPIRY_SECONDS = 300; // 5 minutes
    private static final String CACHE_KEY = "currentToken";

    private final OAuth2TokenService tokenService;
    private final CacheManager cacheManager;

    /**
     * Constructs the TokenCacheServiceImpl.
     *
     * @param tokenService the service used to fetch OAuth2 tokens
     * @param cacheManager the Spring cache manager
     */
    public TokenCacheServiceImpl(OAuth2TokenService tokenService, CacheManager cacheManager) {
        this.tokenService = tokenService;
        this.cacheManager = cacheManager;
    }

    /**
     * Retrieves the current access token.
     * If a token is already cached and valid, it is returned. Otherwise, a new token is requested.
     *
     * @return the current JWT access token
     * @throws OAuth2TokenException if the token refresh fails
     */
    @Override
    public String getToken() {
        log.debug("Fetching token from cache or requesting new one");
        Cache cache = cacheManager.getCache(CacheConfig.TOKEN_CACHE);
        if (cache == null) {
            log.warn("Cache {} not found, fetching fresh token", CacheConfig.TOKEN_CACHE);
            return refreshToken();
        }

        TokenResponse tokenResponse = cache.get(CACHE_KEY, TokenResponse.class);
        if (tokenResponse == null || tokenResponse.expiresWithin(REFRESH_BEFORE_EXPIRY_SECONDS)) {
            log.info("Token is missing or nearing expiry, refreshing");
            return refreshToken();
        }

        return tokenResponse.getAccessToken();
    }

    /**
     * Refreshes the OAuth2 access token by requesting a new one from the server.
     * The new token is then stored in the cache.
     *
     * @return the new JWT access token
     * @throws OAuth2TokenException if the token refresh fails
     */
    @Override
    public synchronized String refreshToken() {
        log.info("Requesting fresh OAuth2 token from server");
        try {
            TokenResponse response = tokenService.getAccessToken();
            Cache cache = cacheManager.getCache(CacheConfig.TOKEN_CACHE);
            if (cache != null) {
                cache.put(CACHE_KEY, response);
            }
            return response.getAccessToken();
        } catch (Exception e) {
            log.error("Failed to refresh token", e);
            // Invalidate cache on failure to ensure next getToken() tries again
            Cache cache = cacheManager.getCache(CacheConfig.TOKEN_CACHE);
            if (cache != null) {
                cache.evict(CACHE_KEY);
            }
            throw e;
        }
    }
}
