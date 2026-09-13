package io.sentinelflow.security.admin;

import java.util.Optional;

/**
 * Interface for admin user storage and lookup.
 * Extension point for JDBC-backed user management in future.
 */
public interface AdminUserStore {

    /**
     * Find an admin user by username.
     *
     * @param username the username to look up
     * @return the admin principal if found
     */
    Optional<AdminPrincipal> findByUsername(String username);

    /**
     * Validate a raw password against an encoded password hash.
     *
     * @param rawPassword     the plaintext password from the login request
     * @param encodedPassword the stored BCrypt hash
     * @return true if the password matches
     */
    boolean validatePassword(String rawPassword, String encodedPassword);
}
