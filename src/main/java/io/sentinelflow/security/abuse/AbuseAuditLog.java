package io.sentinelflow.security.abuse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;

/**
 * Audit log for abuse mitigation actions.
 * Records every mitigation action with full context for compliance and debugging.
 * Uses an in-memory ring buffer with configurable max size.
 */
@Component
public class AbuseAuditLog {

    private static final Logger logger = LoggerFactory.getLogger(AbuseAuditLog.class);
    private static final int DEFAULT_MAX_ENTRIES = 10000;

    private final LinkedList<AuditEntry> entries = new LinkedList<>();
    private final int maxEntries;

    public AbuseAuditLog() {
        this(DEFAULT_MAX_ENTRIES);
    }

    public AbuseAuditLog(int maxEntries) {
        this.maxEntries = maxEntries;
    }

    /**
     * Record a mitigation action.
     */
    public synchronized void record(AuditEntry entry) {
        entries.addFirst(entry);
        // Trim to max size (ring buffer behavior)
        while (entries.size() > maxEntries) {
            entries.removeLast();
        }
        logger.info("Audit: key={}, action={}, severity={}, score={}, reason={}",
            entry.key(), entry.action(), entry.severity(),
            String.format("%.2f", entry.zScore()), entry.reason());
    }

    /**
     * Get paginated audit entries (newest first).
     *
     * @param page page number (0-based)
     * @param size page size
     * @return list of audit entries for the requested page
     */
    public synchronized List<AuditEntry> getEntries(int page, int size) {
        int start = page * size;
        if (start >= entries.size()) {
            return Collections.emptyList();
        }
        int end = Math.min(start + size, entries.size());
        return new ArrayList<>(entries.subList(start, end));
    }

    /**
     * Get total number of audit entries.
     */
    public synchronized int getTotalEntries() {
        return entries.size();
    }

    /**
     * An audit log entry recording a mitigation action.
     */
    public record AuditEntry(
        Instant timestamp,
        String key,
        String reason,
        String severity,
        String anomalyType,
        double zScore,
        MitigationAction action,
        java.time.Duration blockDuration
    ) {}
}
