package dev.bnacar.distributedratelimiter.monitoring.prometheus;

import dev.bnacar.distributedratelimiter.monitoring.MetricsService;
import dev.bnacar.distributedratelimiter.ratelimit.RateLimiterService;
import io.micrometer.prometheusmetrics.PrometheusMeterRegistry;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * Configuration for Prometheus metrics integration.
 * Only activates when Prometheus registry is on the classpath.
 */
@Configuration
@ConditionalOnClass(PrometheusMeterRegistry.class)
public class PrometheusMetricsConfig {

    @Bean
    public RateLimiterMetricsBinder rateLimiterMetricsBinder(
            MetricsService metricsService,
            RateLimiterService rateLimiterService) {
        return new RateLimiterMetricsBinder(metricsService, rateLimiterService);
    }
}
