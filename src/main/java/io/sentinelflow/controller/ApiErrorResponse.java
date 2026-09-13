package io.sentinelflow.controller;

/**
 * Minimal error response for client-facing API failures.
 */
public record ApiErrorResponse(String error) {
}
