package dev.bnacar.distributedratelimiter.security.abuse;

import dev.bnacar.distributedratelimiter.adaptive.AnomalyScore;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class AbuseMitigationServiceTest {

    private AbuseMitigationService service;
    private InMemoryBlockedKeyStore blockedKeyStore;
    private AbuseAuditLog auditLog;

    @BeforeEach
    void setUp() {
        AbuseMitigationProperties properties = new AbuseMitigationProperties();
        properties.setEnabled(true);

        AbuseMitigationProperties.PolicyDefinition critical = new AbuseMitigationProperties.PolicyDefinition();
        critical.setSeverity("CRITICAL");
        critical.setAction(MitigationAction.TEMP_BLOCK);
        critical.setBlockDuration(Duration.ofMinutes(15));

        AbuseMitigationProperties.PolicyDefinition high = new AbuseMitigationProperties.PolicyDefinition();
        high.setSeverity("HIGH");
        high.setAction(MitigationAction.THROTTLE_HARD);
        high.setBlockDuration(Duration.ofMinutes(5));

        AbuseMitigationProperties.PolicyDefinition medium = new AbuseMitigationProperties.PolicyDefinition();
        medium.setSeverity("MEDIUM");
        medium.setAction(MitigationAction.LOG_ONLY);

        properties.setPolicies(List.of(critical, high, medium));

        MitigationPolicy mitigationPolicy = new MitigationPolicy(properties);
        blockedKeyStore = new InMemoryBlockedKeyStore();
        auditLog = new AbuseAuditLog();
        SimpleMeterRegistry meterRegistry = new SimpleMeterRegistry();

        service = new AbuseMitigationService(
            properties, mitigationPolicy, blockedKeyStore, auditLog, meterRegistry);
    }

    @Test
    void onAnomalyDetected_CriticalSeverity_BlocksKey() {
        AnomalyScore score = AnomalyScore.builder()
            .isAnomaly(true)
            .severity("CRITICAL")
            .type("SPIKE")
            .confidence(1.0)
            .zScore(7.0)
            .build();

        AnomalyEvent event = new AnomalyEvent(this, "abusive-key", score);
        service.onAnomalyDetected(event);

        assertTrue(blockedKeyStore.isBlocked("abusive-key"));
        assertEquals(1, auditLog.getTotalEntries());
    }

    @Test
    void onAnomalyDetected_HighSeverity_ThrottlesKey() {
        AnomalyScore score = AnomalyScore.builder()
            .isAnomaly(true)
            .severity("HIGH")
            .type("SUSTAINED_HIGH")
            .confidence(0.9)
            .zScore(5.5)
            .build();

        AnomalyEvent event = new AnomalyEvent(this, "throttle-key", score);
        service.onAnomalyDetected(event);

        assertTrue(blockedKeyStore.isBlocked("throttle-key"));
        assertEquals(1, auditLog.getTotalEntries());
    }

    @Test
    void onAnomalyDetected_MediumSeverity_LogsOnly() {
        AnomalyScore score = AnomalyScore.builder()
            .isAnomaly(true)
            .severity("MEDIUM")
            .type("SUSTAINED_HIGH")
            .confidence(0.7)
            .zScore(4.5)
            .build();

        AnomalyEvent event = new AnomalyEvent(this, "log-only-key", score);
        service.onAnomalyDetected(event);

        assertFalse(blockedKeyStore.isBlocked("log-only-key"));
        assertEquals(1, auditLog.getTotalEntries());

        AbuseAuditLog.AuditEntry entry = auditLog.getEntries(0, 1).get(0);
        assertEquals(MitigationAction.LOG_ONLY, entry.action());
    }

    @Test
    void onAnomalyDetected_WhenDisabled_DoesNothing() {
        // Create service with disabled properties
        AbuseMitigationProperties disabledProps = new AbuseMitigationProperties();
        disabledProps.setEnabled(false);
        MitigationPolicy policy = new MitigationPolicy(disabledProps);
        AbuseMitigationService disabledService = new AbuseMitigationService(
            disabledProps, policy, blockedKeyStore, auditLog, null);

        AnomalyScore score = AnomalyScore.builder()
            .isAnomaly(true)
            .severity("CRITICAL")
            .type("SPIKE")
            .confidence(1.0)
            .zScore(7.0)
            .build();

        AnomalyEvent event = new AnomalyEvent(this, "should-not-block", score);
        disabledService.onAnomalyDetected(event);

        assertFalse(blockedKeyStore.isBlocked("should-not-block"));
        assertEquals(0, auditLog.getTotalEntries());
    }

    @Test
    void onAnomalyDetected_RequireChallenge_ThrowsUnsupported() {
        AbuseMitigationProperties props = new AbuseMitigationProperties();
        props.setEnabled(true);
        AbuseMitigationProperties.PolicyDefinition challengePolicy = new AbuseMitigationProperties.PolicyDefinition();
        challengePolicy.setSeverity("LOW");
        challengePolicy.setAction(MitigationAction.REQUIRE_CHALLENGE);
        props.setPolicies(List.of(challengePolicy));

        MitigationPolicy policy = new MitigationPolicy(props);
        AbuseMitigationService challengeService = new AbuseMitigationService(
            props, policy, blockedKeyStore, auditLog, null);

        AnomalyScore score = AnomalyScore.builder()
            .isAnomaly(true)
            .severity("LOW")
            .type("SUSTAINED_HIGH")
            .confidence(0.5)
            .zScore(3.5)
            .build();

        AnomalyEvent event = new AnomalyEvent(this, "challenge-key", score);
        assertThrows(UnsupportedOperationException.class,
            () -> challengeService.onAnomalyDetected(event));
    }
}
