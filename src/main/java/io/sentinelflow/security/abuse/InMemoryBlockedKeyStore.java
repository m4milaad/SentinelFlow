package io.sentinelflow.security.abuse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Collectors;

/**
 * In-memory implementation of BlockedKeyStore.
 * Uses ConcurrentHashMap with TTL-based expiry on read.
 * Suitable as a fallback when Redis is unavailable or for single-instance deployments.
 */
@Component
public class InMemoryBlockedKeyStore implements BlockedKeyStore {

    private static final Logger logger = LoggerFactory.getLogger(InMemoryBlockedKeyStore.class);

    private final Map<String, BlockEntry> blockedKeys = new ConcurrentHashMap<>();

    @Override
    public void blockKey(String key, Duration duration, String reason) {
        Instant now = Instant.now();
        Instant expiresAt = now.plus(duration);
        blockedKeys.put(key, new BlockEntry(reason, now, expiresAt));
        logger.info("Blocked key '{}' until {} — reason: {}", key, expiresAt, reason);
    }

    @Override
    public boolean isBlocked(String key) {
        BlockEntry entry = blockedKeys.get(key);
        if (entry == null) {
            return false;
        }
        // Check expiry
        if (Instant.now().isAfter(entry.expiresAt())) {
            blockedKeys.remove(key);
            logger.debug("Block expired for key '{}'", key);
            return false;
        }
        return true;
    }

    @Override
    public void unblockKey(String key) {
        BlockEntry removed = blockedKeys.remove(key);
        if (removed != null) {
            logger.info("Manually unblocked key '{}'", key);
        }
    }

    @Override
    public List<BlockedKeyInfo> getBlockedKeys() {
        Instant now = Instant.now();
        // Clean up expired entries and return current ones
        return blockedKeys.entrySet().stream()
            .filter(e -> now.isBefore(e.getValue().expiresAt()))
            .map(e -> new BlockedKeyInfo(
                e.getKey(),
                e.getValue().reason(),
                e.getValue().blockedAt(),
                e.getValue().expiresAt()
            ))
            .collect(Collectors.toList());
    }

    private record BlockEntry(String reason, Instant blockedAt, Instant expiresAt) {}
}
