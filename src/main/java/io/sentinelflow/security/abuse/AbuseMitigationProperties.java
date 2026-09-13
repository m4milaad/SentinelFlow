package io.sentinelflow.security.abuse;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;

/**
 * Configuration properties for abuse mitigation.
 * Bound to {@code sentinel.abuse-mitigation.*} in application properties.
 */
@Configuration
@ConfigurationProperties(prefix = "sentinel.abuse-mitigation")
public class AbuseMitigationProperties {

    private boolean enabled = true;

    private List<PolicyDefinition> policies = new ArrayList<>();

    public boolean isEnabled() {
        return enabled;
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    public List<PolicyDefinition> getPolicies() {
        return policies;
    }

    public void setPolicies(List<PolicyDefinition> policies) {
        this.policies = policies;
    }

    public static class PolicyDefinition {
        private String severity;
        private MitigationAction action = MitigationAction.LOG_ONLY;
        private Duration blockDuration = Duration.ofMinutes(5);

        public String getSeverity() {
            return severity;
        }

        public void setSeverity(String severity) {
            this.severity = severity;
        }

        public MitigationAction getAction() {
            return action;
        }

        public void setAction(MitigationAction action) {
            this.action = action;
        }

        public Duration getBlockDuration() {
            return blockDuration;
        }

        public void setBlockDuration(Duration blockDuration) {
            this.blockDuration = blockDuration;
        }
    }
}
