package dev.bnacar.distributedratelimiter.security.abuse;

import dev.bnacar.distributedratelimiter.adaptive.AnomalyScore;
import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.MeterRegistry;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.event.EventListener;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.time.Instant;

/**
 * Core service that listens for anomaly events and executes mitigation policies.
 * Subscribes to {@link AnomalyEvent} via Spring's event system.
 */
@Service
public class AbuseMitigationService {

    private static final Logger logger = LoggerFactory.getLogger(AbuseMitigationService.class);

    private final AbuseMitigationProperties properties;
    private final MitigationPolicy mitigationPolicy;
    private final BlockedKeyStore blockedKeyStore;
    private final AbuseAuditLog auditLog;
    private final MeterRegistry meterRegistry;

    @Autowired
    public AbuseMitigationService(AbuseMitigationProperties properties,
                                   MitigationPolicy mitigationPolicy,
                                   BlockedKeyStore blockedKeyStore,
                                   AbuseAuditLog auditLog,
                                   @Autowired(required = false) MeterRegistry meterRegistry) {
        this.properties = properties;
        this.mitigationPolicy = mitigationPolicy;
        this.blockedKeyStore = blockedKeyStore;
        this.auditLog = auditLog;
        this.meterRegistry = meterRegistry;
    }

    /**
     * Handle an anomaly event from the AnomalyDetector.
     */
    @EventListener
    public void onAnomalyDetected(AnomalyEvent event) {
        if (!properties.isEnabled()) {
            return;
        }

        AnomalyScore score = event.getAnomalyScore();
        String key = event.getKey();
        String severity = score.getSeverity();

        // Resolve policy for this severity
        MitigationPolicy.PolicyEntry policy = mitigationPolicy.resolve(severity);
        MitigationAction action = policy.action();

        logger.info("Processing anomaly for key '{}': severity={}, type={}, z-score={}, action={}",
            key, severity, score.getType(), String.format("%.2f", score.getZScore()), action);

        // Execute the action
        switch (action) {
            case TEMP_BLOCK:
                blockedKeyStore.blockKey(key, policy.blockDuration(),
                    String.format("Auto-blocked: %s anomaly (z-score=%.2f, type=%s)",
                        severity, score.getZScore(), score.getType()));
                break;

            case THROTTLE_HARD:
                // For throttle, we still block but for a shorter duration
                blockedKeyStore.blockKey(key, policy.blockDuration(),
                    String.format("Throttled: %s anomaly (z-score=%.2f, type=%s)",
                        severity, score.getZScore(), score.getType()));
                break;

            case LOG_ONLY:
                logger.info("LOG_ONLY action for key '{}': severity={}, z-score={}",
                    key, severity, score.getZScore());
                break;

            case REQUIRE_CHALLENGE:
                throw new UnsupportedOperationException(
                    "REQUIRE_CHALLENGE action is reserved for future implementation. " +
                    "Configure a different action for severity: " + severity);
        }

        // Record audit entry
        Duration blockDuration = (action == MitigationAction.LOG_ONLY)
            ? Duration.ZERO : policy.blockDuration();

        auditLog.record(new AbuseAuditLog.AuditEntry(
            Instant.now(),
            key,
            String.format("%s anomaly detected (z-score=%.2f)", severity, score.getZScore()),
            severity,
            score.getType(),
            score.getZScore(),
            action,
            blockDuration
        ));

        // Increment Micrometer counters
        if (meterRegistry != null) {
            Counter.builder("sentinel_abuse_mitigations_total")
                .tag("action", action.name())
                .tag("severity", severity)
                .description("Total abuse mitigation actions taken")
                .register(meterRegistry)
                .increment();
        }
    }
}
