package dev.bnacar.distributedratelimiter.security.abuse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Primary;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Component;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Redis-backed implementation of BlockedKeyStore for distributed abuse mitigation.
 * Stores blocked keys with TTL auto-expiry in Redis so blocks are shared across all instances.
 * Falls back to an internal InMemoryBlockedKeyStore if Redis is unavailable or disabled.
 */
@Component
@Primary
public class RedisBlockedKeyStore implements BlockedKeyStore {

    private static final Logger logger = LoggerFactory.getLogger(RedisBlockedKeyStore.class);

    public static final String KEY_PREFIX = "sentinel:abuse:blocked:";
    public static final String SET_KEY = "sentinel:abuse:blocked-keys";

    private final RedisTemplate<String, Object> redisTemplate;
    private final InMemoryBlockedKeyStore fallback;

    public RedisBlockedKeyStore() {
        this(null, new InMemoryBlockedKeyStore());
    }

    @Autowired
    public RedisBlockedKeyStore(
            @Autowired(required = false) @Qualifier("rateLimiterRedisTemplate") RedisTemplate<String, Object> redisTemplate) {
        this(redisTemplate, new InMemoryBlockedKeyStore());
    }

    public RedisBlockedKeyStore(RedisTemplate<String, Object> redisTemplate, InMemoryBlockedKeyStore fallback) {
        this.redisTemplate = redisTemplate;
        this.fallback = fallback != null ? fallback : new InMemoryBlockedKeyStore();
    }

    @Override
    public void blockKey(String key, Duration duration, String reason) {
        Instant now = Instant.now();
        Instant expiresAt = now.plus(duration);

        if (redisTemplate != null) {
            try {
                String redisKey = KEY_PREFIX + key;
                Map<String, String> data = Map.of(
                    "key", key,
                    "reason", reason,
                    "blockedAt", now.toString(),
                    "expiresAt", expiresAt.toString()
                );
                redisTemplate.opsForValue().set(redisKey, data, duration);
                redisTemplate.opsForSet().add(SET_KEY, key);
                logger.info("Blocked key '{}' in Redis until {} (TTL: {}s) — reason: {}",
                    key, expiresAt, duration.getSeconds(), reason);
                return;
            } catch (Exception e) {
                logger.warn("Redis error while blocking key '{}', falling back to in-memory: {}", key, e.getMessage());
            }
        }

        fallback.blockKey(key, duration, reason);
    }

    @Override
    public boolean isBlocked(String key) {
        if (redisTemplate != null) {
            try {
                Boolean exists = redisTemplate.hasKey(KEY_PREFIX + key);
                if (Boolean.TRUE.equals(exists)) {
                    return true;
                }
                // Check fallback in case it was blocked during a Redis outage
                return fallback.isBlocked(key);
            } catch (Exception e) {
                logger.debug("Redis error checking if key '{}' is blocked, falling back to in-memory: {}", key, e.getMessage());
                return fallback.isBlocked(key);
            }
        }
        return fallback.isBlocked(key);
    }

    @Override
    public void unblockKey(String key) {
        if (redisTemplate != null) {
            try {
                redisTemplate.delete(KEY_PREFIX + key);
                redisTemplate.opsForSet().remove(SET_KEY, key);
                logger.info("Unblocked key '{}' in Redis", key);
            } catch (Exception e) {
                logger.warn("Redis error unblocking key '{}', falling back: {}", key, e.getMessage());
            }
        }
        fallback.unblockKey(key);
    }

    @Override
    public List<BlockedKeyInfo> getBlockedKeys() {
        if (redisTemplate != null) {
            try {
                Set<Object> members = redisTemplate.opsForSet().members(SET_KEY);
                if (members == null || members.isEmpty()) {
                    return fallback.getBlockedKeys();
                }

                List<BlockedKeyInfo> result = new ArrayList<>();
                Instant now = Instant.now();

                for (Object member : members) {
                    String key = member.toString();
                    String redisKey = KEY_PREFIX + key;
                    Object val = redisTemplate.opsForValue().get(redisKey);

                    if (val == null) {
                        // Expired via TTL in Redis, evict member from tracking set
                        redisTemplate.opsForSet().remove(SET_KEY, member);
                    } else if (val instanceof Map<?, ?> map) {
                        String reason = (String) map.get("reason");
                        Instant blockedAt = Instant.parse((String) map.get("blockedAt"));
                        Instant expiresAt = Instant.parse((String) map.get("expiresAt"));
                        if (now.isBefore(expiresAt)) {
                            result.add(new BlockedKeyInfo(key, reason, blockedAt, expiresAt));
                        } else {
                            redisTemplate.opsForSet().remove(SET_KEY, member);
                        }
                    } else {
                        // Generic fallback info if deserialized as a different structure
                        result.add(new BlockedKeyInfo(key, "Blocked in Redis", now, now.plusSeconds(60)));
                    }
                }

                // Also append any entries that were stored in fallback during outage
                for (BlockedKeyInfo fbInfo : fallback.getBlockedKeys()) {
                    if (result.stream().noneMatch(r -> r.key().equals(fbInfo.key()))) {
                        result.add(fbInfo);
                    }
                }

                return result;
            } catch (Exception e) {
                logger.warn("Redis error fetching blocked keys, falling back to in-memory: {}", e.getMessage());
                return fallback.getBlockedKeys();
            }
        }

        return fallback.getBlockedKeys();
    }
}
