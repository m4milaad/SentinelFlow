package io.sentinelflow.monitoring.prometheus;

import io.sentinelflow.monitoring.MetricsService;
import io.sentinelflow.ratelimit.RateLimiterService;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class RateLimiterMetricsBinderTest {

    private MeterRegistry registry;
    private MetricsService metricsService;
    private RateLimiterService rateLimiterService;

    @BeforeEach
    void setUp() {
        registry = new SimpleMeterRegistry();
        metricsService = new MetricsService();
        rateLimiterService = new RateLimiterService(100, 10);
    }

    @Test
    void bindTo_RegistersExpectedMeters() {
        RateLimiterMetricsBinder binder = new RateLimiterMetricsBinder(metricsService, rateLimiterService);
        binder.bindTo(registry);

        // Verify all expected meters are registered
        assertNotNull(registry.find("sentinel_active_keys").gauge(),
            "sentinel_active_keys gauge should be registered");
        assertNotNull(registry.find("sentinel_requests_allowed_total").gauge(),
            "sentinel_requests_allowed_total gauge should be registered");
        assertNotNull(registry.find("sentinel_requests_denied_total").gauge(),
            "sentinel_requests_denied_total gauge should be registered");
        assertNotNull(registry.find("sentinel_redis_connected").gauge(),
            "sentinel_redis_connected gauge should be registered");
    }

    @Test
    void activeKeysGauge_ReflectsRateLimiterState() {
        RateLimiterMetricsBinder binder = new RateLimiterMetricsBinder(metricsService, rateLimiterService);
        binder.bindTo(registry);

        // Initially no keys
        assertEquals(0.0, registry.find("sentinel_active_keys").gauge().value());

        // Add traffic to create buckets
        rateLimiterService.isAllowed("key1", 1);
        rateLimiterService.isAllowed("key2", 1);

        assertEquals(2.0, registry.find("sentinel_active_keys").gauge().value());
    }

    @Test
    void requestCounters_ReflectMetricsServiceState() {
        RateLimiterMetricsBinder binder = new RateLimiterMetricsBinder(metricsService, rateLimiterService);
        binder.bindTo(registry);

        // Initially zero
        assertEquals(0.0, registry.find("sentinel_requests_allowed_total").gauge().value());
        assertEquals(0.0, registry.find("sentinel_requests_denied_total").gauge().value());

        // Record some metrics
        metricsService.recordAllowedRequest("test-key");
        metricsService.recordAllowedRequest("test-key");
        metricsService.recordDeniedRequest("test-key");

        assertEquals(2.0, registry.find("sentinel_requests_allowed_total").gauge().value());
        assertEquals(1.0, registry.find("sentinel_requests_denied_total").gauge().value());
    }

    @Test
    void redisConnectedGauge_ReflectsState() {
        RateLimiterMetricsBinder binder = new RateLimiterMetricsBinder(metricsService, rateLimiterService);
        binder.bindTo(registry);

        // Default is disconnected
        assertEquals(0.0, registry.find("sentinel_redis_connected").gauge().value());

        // Simulate connection
        metricsService.setRedisConnected(true);
        assertEquals(1.0, registry.find("sentinel_redis_connected").gauge().value());
    }
}
