package dev.bnacar.distributedratelimiter.security.abuse;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class MitigationPolicyTest {

    private MitigationPolicy policy;

    @BeforeEach
    void setUp() {
        AbuseMitigationProperties properties = new AbuseMitigationProperties();

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
        medium.setBlockDuration(Duration.ZERO);

        properties.setPolicies(List.of(critical, high, medium));
        policy = new MitigationPolicy(properties);
    }

    @Test
    void resolve_CriticalSeverity_ReturnsTempBlock() {
        MitigationPolicy.PolicyEntry entry = policy.resolve("CRITICAL");
        assertEquals(MitigationAction.TEMP_BLOCK, entry.action());
        assertEquals(Duration.ofMinutes(15), entry.blockDuration());
    }

    @Test
    void resolve_HighSeverity_ReturnsThrottleHard() {
        MitigationPolicy.PolicyEntry entry = policy.resolve("HIGH");
        assertEquals(MitigationAction.THROTTLE_HARD, entry.action());
        assertEquals(Duration.ofMinutes(5), entry.blockDuration());
    }

    @Test
    void resolve_MediumSeverity_ReturnsLogOnly() {
        MitigationPolicy.PolicyEntry entry = policy.resolve("MEDIUM");
        assertEquals(MitigationAction.LOG_ONLY, entry.action());
    }

    @Test
    void resolve_UnknownSeverity_DefaultsToLogOnly() {
        MitigationPolicy.PolicyEntry entry = policy.resolve("UNKNOWN");
        assertEquals(MitigationAction.LOG_ONLY, entry.action());
        assertEquals(Duration.ZERO, entry.blockDuration());
    }

    @Test
    void resolve_CaseInsensitive() {
        MitigationPolicy.PolicyEntry entry = policy.resolve("critical");
        assertEquals(MitigationAction.TEMP_BLOCK, entry.action());
    }

    @Test
    void resolve_LowSeverity_DefaultsToLogOnly() {
        MitigationPolicy.PolicyEntry entry = policy.resolve("LOW");
        assertEquals(MitigationAction.LOG_ONLY, entry.action());
    }
}
