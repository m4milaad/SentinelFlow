package io.sentinelflow.ratelimit;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.test.context.TestPropertySource;

import io.sentinelflow.TestcontainersConfiguration;

import static org.junit.jupiter.api.Assertions.*;

@SpringBootTest
@Import(TestcontainersConfiguration.class)
@TestPropertySource(properties = {
    "ratelimiter.redis.enabled=true",
    "ratelimiter.capacity=5",
    "ratelimiter.refillRate=1"
})
class SentinelFlowServiceTest {

    @Autowired
    private SentinelFlowService sentinelFlowService;

    @Autowired
    private RedisTemplate<String, Object> redisTemplate;

    @BeforeEach
    void setUp() {
        // Clean up any existing test data
        sentinelFlowService.clearAllBuckets();
    }

    @Test
    void testRedisBackendIsUsed() {
        assertTrue(sentinelFlowService.isUsingRedis());
        assertFalse(sentinelFlowService.isUsingFallback());
    }

    @Test
    void testBasicRateLimit() {
        String key = "test:basic";
        
        // Should allow consuming within capacity
        assertTrue(sentinelFlowService.isAllowed(key, 3));
        assertTrue(sentinelFlowService.isAllowed(key, 2));
        
        // Should reject when capacity is exceeded
        assertFalse(sentinelFlowService.isAllowed(key, 1));
    }

    @Test
    void testDistributedRateLimit() {
        String key = "test:distributed";
        
        // Create two instances (simulating different app instances)
        // Use a configuration that matches the test properties
        RateLimiterConfiguration config = new RateLimiterConfiguration();
        config.setCapacity(5);
        config.setRefillRate(1);
        ConfigurationResolver resolver = new ConfigurationResolver(config);
        SentinelFlowService instance1 = new SentinelFlowService(resolver, redisTemplate);
        SentinelFlowService instance2 = new SentinelFlowService(resolver, redisTemplate);
        
        // Consume tokens from both instances
        assertTrue(instance1.isAllowed(key, 2));
        assertTrue(instance2.isAllowed(key, 2));
        
        // Should have consumed 4 out of 5 tokens total
        assertTrue(instance1.isAllowed(key, 1));
        
        // No more tokens should be available from either instance
        assertFalse(instance1.isAllowed(key, 1));
        assertFalse(instance2.isAllowed(key, 1));
    }

    @Test
    void testZeroTokenConsumption() {
        String key = "test:zero";
        assertFalse(sentinelFlowService.isAllowed(key, 0));
    }

    @Test
    void testNegativeTokenConsumption() {
        String key = "test:negative";
        assertFalse(sentinelFlowService.isAllowed(key, -1));
    }

    @Test
    void testMultipleKeys() {
        String key1 = "test:key1";
        String key2 = "test:key2";
        
        // Each key should have independent limits
        assertTrue(sentinelFlowService.isAllowed(key1, 5));
        assertTrue(sentinelFlowService.isAllowed(key2, 5));
        
        // Both keys should be exhausted independently
        assertFalse(sentinelFlowService.isAllowed(key1, 1));
        assertFalse(sentinelFlowService.isAllowed(key2, 1));
    }

    @Test
    void testTokenRefill() throws InterruptedException {
        String key = "test:refill";
        
        // Consume all tokens
        assertTrue(sentinelFlowService.isAllowed(key, 5));
        assertFalse(sentinelFlowService.isAllowed(key, 1));
        
        // Wait for refill (refill rate is 1 token per second)
        Thread.sleep(1100);
        
        // Should have refilled 1 token
        assertTrue(sentinelFlowService.isAllowed(key, 1));
        assertFalse(sentinelFlowService.isAllowed(key, 1));
    }

    @Test
    void testConcurrentAccessAcrossInstances() throws InterruptedException {
        String key = "test:concurrent";
        final int threadCount = 10;
        final int tokensPerThread = 1;
        
        // Create multiple service instances with proper configuration
        RateLimiterConfiguration config = new RateLimiterConfiguration();
        config.setCapacity(5);
        config.setRefillRate(1);
        ConfigurationResolver resolver = new ConfigurationResolver(config);
        SentinelFlowService[] instances = new SentinelFlowService[5];
        for (int i = 0; i < instances.length; i++) {
            instances[i] = new SentinelFlowService(resolver, redisTemplate);
        }
        
        Thread[] threads = new Thread[threadCount];
        boolean[] results = new boolean[threadCount];
        
        // Create threads that use different service instances
        for (int i = 0; i < threadCount; i++) {
            final int index = i;
            final SentinelFlowService instance = instances[i % instances.length];
            threads[i] = new Thread(() -> {
                results[index] = instance.isAllowed(key, tokensPerThread);
            });
        }
        
        // Start all threads
        for (Thread thread : threads) {
            thread.start();
        }
        
        // Wait for all threads to complete
        for (Thread thread : threads) {
            thread.join();
        }
        
        // Count successful requests
        int successCount = 0;
        for (boolean result : results) {
            if (result) successCount++;
        }
        
        // Should only allow 5 successful requests (the capacity)
        assertEquals(5, successCount);
    }

    @Test
    void testClearAllBuckets() {
        String key = "test:clear";
        
        // Use some tokens
        assertTrue(sentinelFlowService.isAllowed(key, 3));
        
        // Clear buckets
        sentinelFlowService.clearAllBuckets();
        
        // Should have full capacity again
        assertTrue(sentinelFlowService.isAllowed(key, 5));
    }
}