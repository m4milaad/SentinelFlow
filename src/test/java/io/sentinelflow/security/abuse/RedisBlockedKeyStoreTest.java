package io.sentinelflow.security.abuse;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.data.redis.RedisConnectionFailureException;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.core.SetOperations;
import org.springframework.data.redis.core.ValueOperations;

import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

class RedisBlockedKeyStoreTest {

    private RedisTemplate<String, Object> redisTemplate;
    private ValueOperations<String, Object> valueOperations;
    private SetOperations<String, Object> setOperations;
    private InMemoryBlockedKeyStore fallback;
    private RedisBlockedKeyStore keyStore;

    @BeforeEach
    @SuppressWarnings("unchecked")
    void setUp() {
        redisTemplate = mock(RedisTemplate.class);
        valueOperations = mock(ValueOperations.class);
        setOperations = mock(SetOperations.class);
        fallback = new InMemoryBlockedKeyStore();

        when(redisTemplate.opsForValue()).thenReturn(valueOperations);
        when(redisTemplate.opsForSet()).thenReturn(setOperations);

        keyStore = new RedisBlockedKeyStore(redisTemplate, fallback);
    }

    @Test
    void blockKey_StoresInRedisWithTtlAndSet() {
        Duration duration = Duration.ofMinutes(15);
        keyStore.blockKey("bad-actor", duration, "Excessive rate");

        verify(valueOperations).set(
            eq("sentinel:abuse:blocked:bad-actor"),
            any(Map.class),
            eq(duration)
        );
        verify(setOperations).add(
            eq("sentinel:abuse:blocked-keys"),
            eq("bad-actor")
        );
    }

    @Test
    void isBlocked_KeyExistsInRedis_ReturnsTrue() {
        when(redisTemplate.hasKey("sentinel:abuse:blocked:bad-actor")).thenReturn(true);

        assertTrue(keyStore.isBlocked("bad-actor"));
        verify(redisTemplate).hasKey("sentinel:abuse:blocked:bad-actor");
    }

    @Test
    void isBlocked_KeyMissingInRedis_ReturnsFalse() {
        when(redisTemplate.hasKey("sentinel:abuse:blocked:innocent")).thenReturn(false);

        assertFalse(keyStore.isBlocked("innocent"));
    }

    @Test
    void unblockKey_DeletesKeyAndRemovesFromSet() {
        keyStore.unblockKey("bad-actor");

        verify(redisTemplate).delete("sentinel:abuse:blocked:bad-actor");
        verify(setOperations).remove("sentinel:abuse:blocked-keys", "bad-actor");
    }

    @Test
    void getBlockedKeys_ParsesRedisEntries() {
        when(setOperations.members("sentinel:abuse:blocked-keys"))
            .thenReturn(Set.of("bad-actor"));

        Instant now = Instant.now();
        Instant future = now.plus(Duration.ofMinutes(10));
        Map<String, String> data = Map.of(
            "key", "bad-actor",
            "reason", "Spike anomaly",
            "blockedAt", now.toString(),
            "expiresAt", future.toString()
        );
        when(valueOperations.get("sentinel:abuse:blocked:bad-actor")).thenReturn(data);

        List<BlockedKeyStore.BlockedKeyInfo> blocked = keyStore.getBlockedKeys();

        assertEquals(1, blocked.size());
        assertEquals("bad-actor", blocked.get(0).key());
        assertEquals("Spike anomaly", blocked.get(0).reason());
    }

    @Test
    void getBlockedKeys_CleansUpExpiredEntries() {
        when(setOperations.members("sentinel:abuse:blocked-keys"))
            .thenReturn(Set.of("expired-key"));

        when(valueOperations.get("sentinel:abuse:blocked:expired-key")).thenReturn(null);

        List<BlockedKeyStore.BlockedKeyInfo> blocked = keyStore.getBlockedKeys();

        assertTrue(blocked.isEmpty());
        verify(setOperations).remove("sentinel:abuse:blocked-keys", "expired-key");
    }

    @Test
    void fallbackToInMemory_WhenRedisThrowsException() {
        doThrow(new RedisConnectionFailureException("Redis offline"))
            .when(valueOperations).set(anyString(), any(), any(Duration.class));

        Duration duration = Duration.ofMinutes(5);
        // Should not throw, should fall back to in-memory store
        assertDoesNotThrow(() -> keyStore.blockKey("fallback-key", duration, "Fallback test"));

        // Verify key is blocked in fallback
        when(redisTemplate.hasKey(anyString()))
            .thenThrow(new RedisConnectionFailureException("Redis offline"));

        assertTrue(keyStore.isBlocked("fallback-key"));
    }

    @Test
    void operatesGracefully_WhenRedisTemplateIsNull() {
        RedisBlockedKeyStore nullTemplateStore = new RedisBlockedKeyStore(null, fallback);

        Duration duration = Duration.ofMinutes(10);
        nullTemplateStore.blockKey("null-redis-key", duration, "Local block");

        assertTrue(nullTemplateStore.isBlocked("null-redis-key"));
        assertEquals(1, nullTemplateStore.getBlockedKeys().size());

        nullTemplateStore.unblockKey("null-redis-key");
        assertFalse(nullTemplateStore.isBlocked("null-redis-key"));
    }
}
