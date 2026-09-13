package io.sentinelflow.monitoring.prometheus;

import io.sentinelflow.monitoring.MetricsService;
import io.sentinelflow.ratelimit.RateLimiterService;
import io.micrometer.core.instrument.Gauge;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.binder.MeterBinder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Bridges existing rate limiter metrics to Micrometer/Prometheus.
 * Pure instrumentation — does not modify business logic.
 */
public class RateLimiterMetricsBinder implements MeterBinder {

    private static final Logger logger = LoggerFactory.getLogger(RateLimiterMetricsBinder.class);

    private final MetricsService metricsService;
    private final RateLimiterService rateLimiterService;

    public RateLimiterMetricsBinder(MetricsService metricsService,
                                     RateLimiterService rateLimiterService) {
        this.metricsService = metricsService;
        this.rateLimiterService = rateLimiterService;
    }

    @Override
    public void bindTo(MeterRegistry registry) {
        // Gauge: active keys count
        Gauge.builder("sentinel_active_keys", rateLimiterService, RateLimiterService::getBucketCount)
            .description("Number of currently active rate limiting keys")
            .register(registry);

        // Gauge: total allowed requests (from MetricsService counters)
        Gauge.builder("sentinel_requests_allowed_total", metricsService,
                ms -> ms.getMetrics().getTotalAllowedRequests())
            .description("Total number of allowed requests")
            .register(registry);

        // Gauge: total denied requests
        Gauge.builder("sentinel_requests_denied_total", metricsService,
                ms -> ms.getMetrics().getTotalDeniedRequests())
            .description("Total number of denied/rate-limited requests")
            .register(registry);

        // Gauge: Redis connectivity
        Gauge.builder("sentinel_redis_connected", metricsService,
                ms -> ms.isRedisConnected() ? 1.0 : 0.0)
            .description("Whether the application is connected to Redis (1=connected, 0=disconnected)")
            .register(registry);

        logger.info("Rate limiter metrics bound to Micrometer registry");
    }
}
