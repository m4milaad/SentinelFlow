package io.sentinelflow.security.abuse;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import java.io.IOException;
import java.time.Duration;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class AbuseMitigationFilterTest {

    private InMemoryBlockedKeyStore blockedKeyStore;
    private AbuseMitigationFilter filter;

    @BeforeEach
    void setUp() {
        AbuseMitigationProperties properties = new AbuseMitigationProperties();
        properties.setEnabled(true);

        blockedKeyStore = new InMemoryBlockedKeyStore();
        filter = new AbuseMitigationFilter(blockedKeyStore, properties);
    }

    @Test
    void doFilter_BlockedKey_Returns429() throws ServletException, IOException {
        blockedKeyStore.blockKey("blocked-key", Duration.ofMinutes(15), "Test block");

        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/api/ratelimit/check");
        request.addHeader("X-Api-Key", "blocked-key");
        MockHttpServletResponse response = new MockHttpServletResponse();
        FilterChain chain = mock(FilterChain.class);

        filter.doFilterInternal(request, response, chain);

        assertEquals(429, response.getStatus());
        assertEquals("60", response.getHeader("Retry-After"));
        assertTrue(response.getContentAsString().contains("temporarily blocked"));
        verify(chain, never()).doFilter(request, response);
    }

    @Test
    void doFilter_UnblockedKey_PassesThrough() throws ServletException, IOException {
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/api/ratelimit/check");
        request.addHeader("X-Api-Key", "normal-key");
        MockHttpServletResponse response = new MockHttpServletResponse();
        FilterChain chain = mock(FilterChain.class);

        filter.doFilterInternal(request, response, chain);

        verify(chain).doFilter(request, response);
    }

    @Test
    void doFilter_NoKey_PassesThrough() throws ServletException, IOException {
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/api/ratelimit/check");
        MockHttpServletResponse response = new MockHttpServletResponse();
        FilterChain chain = mock(FilterChain.class);

        filter.doFilterInternal(request, response, chain);

        verify(chain).doFilter(request, response);
    }

    @Test
    void doFilter_NonApiPath_SkipsCheck() throws ServletException, IOException {
        blockedKeyStore.blockKey("blocked-key", Duration.ofMinutes(15), "Test block");

        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/admin/keys");
        request.addHeader("X-Api-Key", "blocked-key");
        MockHttpServletResponse response = new MockHttpServletResponse();
        FilterChain chain = mock(FilterChain.class);

        filter.doFilterInternal(request, response, chain);

        // Non-API paths should not be checked
        verify(chain).doFilter(request, response);
    }

    @Test
    void doFilter_ExpiredBlock_PassesThrough() throws ServletException, IOException {
        blockedKeyStore.blockKey("expired-key", Duration.ofMillis(1), "Short block");

        // Wait for expiry
        try {
            Thread.sleep(50);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }

        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/api/ratelimit/check");
        request.addHeader("X-Api-Key", "expired-key");
        MockHttpServletResponse response = new MockHttpServletResponse();
        FilterChain chain = mock(FilterChain.class);

        filter.doFilterInternal(request, response, chain);

        verify(chain).doFilter(request, response);
    }

    @Test
    void doFilter_WhenDisabled_AlwaysPassesThrough() throws ServletException, IOException {
        AbuseMitigationProperties disabledProps = new AbuseMitigationProperties();
        disabledProps.setEnabled(false);
        AbuseMitigationFilter disabledFilter = new AbuseMitigationFilter(blockedKeyStore, disabledProps);

        blockedKeyStore.blockKey("blocked-key", Duration.ofMinutes(15), "Test block");

        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/api/ratelimit/check");
        request.addHeader("X-Api-Key", "blocked-key");
        MockHttpServletResponse response = new MockHttpServletResponse();
        FilterChain chain = mock(FilterChain.class);

        disabledFilter.doFilterInternal(request, response, chain);

        verify(chain).doFilter(request, response);
    }

    @Test
    void doFilter_KeyFromQueryParam_IsChecked() throws ServletException, IOException {
        blockedKeyStore.blockKey("param-key", Duration.ofMinutes(15), "Test block");

        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/api/ratelimit/check");
        request.setParameter("key", "param-key");
        MockHttpServletResponse response = new MockHttpServletResponse();
        FilterChain chain = mock(FilterChain.class);

        filter.doFilterInternal(request, response, chain);

        assertEquals(429, response.getStatus());
    }
}
