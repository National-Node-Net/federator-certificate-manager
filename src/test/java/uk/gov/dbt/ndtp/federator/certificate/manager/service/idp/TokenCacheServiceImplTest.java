/*
 * SPDX-License-Identifier: Apache-2.0
 * © Crown Copyright 2026. This work has been developed by the National Digital Twin Programme and is legally
 * attributed to the UK's Department for Business, Innovation, Science and Trade (BIST) as the governing entity.
 */

package uk.gov.dbt.ndtp.federator.certificate.manager.service.idp;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.*;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.cache.Cache;
import org.springframework.cache.CacheManager;
import uk.gov.dbt.ndtp.federator.certificate.manager.config.CacheConfig;
import uk.gov.dbt.ndtp.federator.certificate.manager.exception.OAuth2TokenException;

@ExtendWith(MockitoExtension.class)
class TokenCacheServiceImplTest {

    @Mock
    private OAuth2TokenService tokenService;

    @Mock
    private CacheManager cacheManager;

    @Mock
    private Cache cache;

    @InjectMocks
    private TokenCacheServiceImpl cacheService;

    @BeforeEach
    void setUp() {
        lenient().when(cacheManager.getCache(CacheConfig.TOKEN_CACHE)).thenReturn(cache);
    }

    @Test
    void getToken_usesCacheWhenValid() {
        TokenResponse validResponse = new TokenResponse("token123", 600);
        when(cache.get("currentToken", TokenResponse.class)).thenReturn(validResponse);

        String token = cacheService.getToken();

        assertEquals("token123", token);
        verify(tokenService, never()).getAccessToken();
    }

    @Test
    void getToken_refreshesWhenCacheEmpty() {
        when(cache.get("currentToken", TokenResponse.class)).thenReturn(null);
        when(tokenService.getAccessToken()).thenReturn(new TokenResponse("newToken", 600));

        String token = cacheService.getToken();

        assertEquals("newToken", token);
        verify(cache).put(eq("currentToken"), any(TokenResponse.class));
    }

    @Test
    void getToken_refreshesWhenCacheIsNull() {
        when(cacheManager.getCache(CacheConfig.TOKEN_CACHE)).thenReturn(null);
        when(tokenService.getAccessToken()).thenReturn(new TokenResponse("noCacheToken", 600));

        String token = cacheService.getToken();

        assertEquals("noCacheToken", token);
        verify(tokenService).getAccessToken();
    }

    @Test
    void getToken_refreshesWhenNearingExpiry() {
        TokenResponse nearingExpiry = new TokenResponse("oldToken", 100); // threshold is 300
        when(cache.get("currentToken", TokenResponse.class)).thenReturn(nearingExpiry);
        when(tokenService.getAccessToken()).thenReturn(new TokenResponse("newToken", 600));

        String token = cacheService.getToken();

        assertEquals("newToken", token);
        verify(tokenService).getAccessToken();
        verify(cache).put(eq("currentToken"), any(TokenResponse.class));
    }

    @Test
    void refreshToken_forcesNewFetch() {
        when(tokenService.getAccessToken()).thenReturn(new TokenResponse("forcedToken", 600));

        String token = cacheService.refreshToken();

        assertEquals("forcedToken", token);
        verify(cache).put(eq("currentToken"), any(TokenResponse.class));
    }

    @Test
    void refreshToken_evictsOnFailure() {
        when(tokenService.getAccessToken()).thenThrow(new OAuth2TokenException("Service failure"));

        assertThrows(OAuth2TokenException.class, () -> cacheService.refreshToken());

        verify(cache).evict("currentToken");
    }

    @Test
    void refreshToken_handlesCacheNullOnSuccess() {
        when(tokenService.getAccessToken()).thenReturn(new TokenResponse("token", 600));
        when(cacheManager.getCache(CacheConfig.TOKEN_CACHE)).thenReturn(null);

        String token = cacheService.refreshToken();

        assertEquals("token", token);
        verify(tokenService).getAccessToken();
    }

    @Test
    void refreshToken_handlesCacheNullOnFailure() {
        when(tokenService.getAccessToken()).thenThrow(new OAuth2TokenException("fail"));
        when(cacheManager.getCache(CacheConfig.TOKEN_CACHE)).thenReturn(null);

        assertThrows(OAuth2TokenException.class, () -> cacheService.refreshToken());
        verify(tokenService).getAccessToken();
    }
}
