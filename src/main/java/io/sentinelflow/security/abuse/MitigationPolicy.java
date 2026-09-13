package io.sentinelflow.security.abuse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.time.Duration;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Resolves mitigation actions based on anomaly severity and configured policies.
 */
@Component
public class MitigationPolicy {

    private static final Logger logger = LoggerFactory.getLogger(MitigationPolicy.class);

    private final Map<String, PolicyEntry> policyMap = new ConcurrentHashMap<>();

    public MitigationPolicy(AbuseMitigationProperties properties) {
        for (AbuseMitigationProperties.PolicyDefinition def : properties.getPolicies()) {
            policyMap.put(def.getSeverity().toUpperCase(), new PolicyEntry(
                def.getAction(),
                def.getBlockDuration()
            ));
            logger.info("Loaded mitigation policy: severity={} -> action={}, duration={}",
                def.getSeverity(), def.getAction(), def.getBlockDuration());
        }
    }

    /**
     * Resolve the mitigation action for a given severity.
     *
     * @param severity the anomaly severity (e.g., CRITICAL, HIGH, MEDIUM)
     * @return the resolved policy entry, or LOG_ONLY if no policy matches
     */
    public PolicyEntry resolve(String severity) {
        PolicyEntry entry = policyMap.get(severity.toUpperCase());
        if (entry == null) {
            logger.debug("No policy for severity '{}', defaulting to LOG_ONLY", severity);
            return new PolicyEntry(MitigationAction.LOG_ONLY, Duration.ZERO);
        }
        return entry;
    }

    /**
     * A resolved policy entry with action and block duration.
     */
    public record PolicyEntry(MitigationAction action, Duration blockDuration) {}
}
