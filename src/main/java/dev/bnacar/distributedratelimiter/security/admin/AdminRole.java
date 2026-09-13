package dev.bnacar.distributedratelimiter.security.admin;

/**
 * Admin roles for scoped access to admin endpoints.
 * Hierarchical: SUPER_ADMIN > OPERATOR > VIEWER
 */
public enum AdminRole {
    VIEWER("ROLE_VIEWER"),
    OPERATOR("ROLE_OPERATOR"),
    SUPER_ADMIN("ROLE_SUPER_ADMIN");

    private final String authority;

    AdminRole(String authority) {
        this.authority = authority;
    }

    public String getAuthority() {
        return authority;
    }
}
