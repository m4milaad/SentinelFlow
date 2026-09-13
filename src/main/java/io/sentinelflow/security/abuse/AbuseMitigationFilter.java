package io.sentinelflow.security.abuse;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

/**
 * Filter that short-circuits requests from blocked keys before they reach
 * the rate limiter. Returns 429 Too Many Requests with a Retry-After header.
 */
@Component
@Order(0) // Run before SecurityFilter (order 1) and CorrelationIdFilter (order 1)
public class AbuseMitigationFilter extends OncePerRequestFilter {

    private static final Logger logger = LoggerFactory.getLogger(AbuseMitigationFilter.class);

    private final BlockedKeyStore blockedKeyStore;
    private final AbuseMitigationProperties properties;

    @org.springframework.beans.factory.annotation.Autowired
    public AbuseMitigationFilter(@org.springframework.beans.factory.annotation.Autowired(required = false) BlockedKeyStore blockedKeyStore,
                                 @org.springframework.beans.factory.annotation.Autowired(required = false) AbuseMitigationProperties properties) {
        this.blockedKeyStore = blockedKeyStore;
        this.properties = properties;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                     HttpServletResponse response,
                                     FilterChain filterChain)
            throws ServletException, IOException {

        if (properties == null || !properties.isEnabled() || blockedKeyStore == null) {
            filterChain.doFilter(request, response);
            return;
        }

        // Only apply to API endpoints
        String path = request.getRequestURI();
        if (!path.startsWith("/api/")) {
            filterChain.doFilter(request, response);
            return;
        }

        // Extract the rate limit key from the request
        // The key is typically sent in the request body, but for the filter
        // we check common header/parameter sources
        String key = extractKey(request);

        if (key != null && blockedKeyStore.isBlocked(key)) {
            logger.warn("Blocked request from key '{}' to {}", key, path);
            response.setStatus(429); // 429 Too Many Requests
            response.setHeader("Retry-After", "60");
            response.setContentType("application/json");
            response.getWriter().write(
                "{\"error\":\"Too Many Requests\"," +
                "\"message\":\"Your key has been temporarily blocked due to detected abuse\"," +
                "\"retryAfter\":60}"
            );
            return;
        }

        filterChain.doFilter(request, response);
    }

    /**
     * Extract the rate limit key from request headers or parameters.
     * Checks X-Api-Key header and 'key' query parameter.
     */
    private String extractKey(HttpServletRequest request) {
        // Check X-Api-Key header first
        String apiKey = request.getHeader("X-Api-Key");
        if (apiKey != null && !apiKey.isBlank()) {
            return apiKey;
        }

        // Check query parameter
        String keyParam = request.getParameter("key");
        if (keyParam != null && !keyParam.isBlank()) {
            return keyParam;
        }

        return null;
    }
}
