package io.sentinelflow.security.abuse;

import io.sentinelflow.adaptive.AnomalyScore;
import org.springframework.context.ApplicationEvent;

import java.time.Instant;

/**
 * Spring application event published when an anomaly is detected.
 * Bridges the AnomalyDetector to the AbuseMitigationService via the event bus.
 */
public class AnomalyEvent extends ApplicationEvent {

    private static final long serialVersionUID = 1L;

    private final String key;
    private final transient AnomalyScore anomalyScore;
    private final Instant detectedAt;

    public AnomalyEvent(Object source, String key, AnomalyScore anomalyScore) {
        super(source);
        this.key = key;
        this.anomalyScore = anomalyScore;
        this.detectedAt = Instant.now();
    }

    public String getKey() {
        return key;
    }

    public AnomalyScore getAnomalyScore() {
        return anomalyScore;
    }

    public Instant getDetectedAt() {
        return detectedAt;
    }
}
