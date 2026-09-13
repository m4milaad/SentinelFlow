package io.sentinelflow.security.admin;

import java.util.Set;

/**
 * Represents an authenticated admin user with their assigned roles.
 */
public record AdminPrincipal(
    String username,
    Set<AdminRole> roles,
    String passwordHash
) {
    /**
     * Create an AdminPrincipal without a password hash (e.g., from a validated JWT).
     */
    public static AdminPrincipal fromToken(String username, Set<AdminRole> roles) {
        return new AdminPrincipal(username, roles, null);
    }
}
