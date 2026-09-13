package io.sentinelflow.security.abuse;

import java.time.Duration;
import java.time.Instant;
import java.util.List;

/**
 * Interface for storing and querying blocked keys.
 * Implementations should handle TTL-based auto-expiry.
 */
public interface BlockedKeyStore {

    /**
     * Block a key for the specified duration.
     *
     * @param key      the rate limit key to block
     * @param duration how long to block
     * @param reason   why the key was blocked
     */
    void blockKey(String key, Duration duration, String reason);

    /**
     * Check if a key is currently blocked.
     *
     * @param key the rate limit key
     * @return true if the key is blocked
     */
    boolean isBlocked(String key);

    /**
     * Manually unblock a key.
     *
     * @param key the rate limit key to unblock
     */
    void unblockKey(String key);

    /**
     * Get all currently blocked keys with their metadata.
     *
     * @return list of blocked key info
     */
    List<BlockedKeyInfo> getBlockedKeys();

    /**
     * Information about a blocked key.
     */
    record BlockedKeyInfo(
        String key,
        String reason,
        Instant blockedAt,
        Instant expiresAt
    ) {}
}
