package dev.bnacar.distributedratelimiter.security.abuse;

/**
 * Actions that can be taken in response to detected abuse.
 */
public enum MitigationAction {
    /**
     * Log the event but take no blocking action.
     */
    LOG_ONLY,

    /**
     * Apply a significantly reduced rate limit to the key.
     */
    THROTTLE_HARD,

    /**
     * Temporarily block all requests from the key.
     */
    TEMP_BLOCK,

    /**
     * Reserved hook for future challenge-based verification (e.g., CAPTCHA).
     * Currently not implemented.
     */
    REQUIRE_CHALLENGE
}
