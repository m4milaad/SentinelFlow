package io.sentinelflow.security.admin;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;

/**
 * Configuration properties for admin authentication.
 * Bound to {@code sentinel.security.admin.*} in application properties.
 */
@Configuration
@ConfigurationProperties(prefix = "sentinel.security.admin")
public class AdminSecurityProperties {

    /**
     * Authentication mode: jwt (default) or basic-legacy (deprecated).
     */
    private String authMode = "jwt";

    private Jwt jwt = new Jwt();

    private List<UserDefinition> users = new ArrayList<>();

    public String getAuthMode() {
        return authMode;
    }

    public void setAuthMode(String authMode) {
        this.authMode = authMode;
    }

    public Jwt getJwt() {
        return jwt;
    }

    public void setJwt(Jwt jwt) {
        this.jwt = jwt;
    }

    public List<UserDefinition> getUsers() {
        return users;
    }

    public void setUsers(List<UserDefinition> users) {
        this.users = users;
    }

    public static class Jwt {
        private String issuer = "traffic-sentinel";
        private String audience = "admin-api";
        /**
         * HMAC signing key. Required — no default. Set via ADMIN_JWT_SIGNING_KEY env var.
         */
        private String signingKey;
        private Duration tokenTtl = Duration.ofHours(1);

        public String getIssuer() {
            return issuer;
        }

        public void setIssuer(String issuer) {
            this.issuer = issuer;
        }

        public String getAudience() {
            return audience;
        }

        public void setAudience(String audience) {
            this.audience = audience;
        }

        public String getSigningKey() {
            return signingKey;
        }

        public void setSigningKey(String signingKey) {
            this.signingKey = signingKey;
        }

        public Duration getTokenTtl() {
            return tokenTtl;
        }

        public void setTokenTtl(Duration tokenTtl) {
            this.tokenTtl = tokenTtl;
        }
    }

    public static class UserDefinition {
        private String username;
        private String passwordHash;
        private List<String> roles = new ArrayList<>();

        public String getUsername() {
            return username;
        }

        public void setUsername(String username) {
            this.username = username;
        }

        public String getPasswordHash() {
            return passwordHash;
        }

        public void setPasswordHash(String passwordHash) {
            this.passwordHash = passwordHash;
        }

        public List<String> getRoles() {
            return roles;
        }

        public void setRoles(List<String> roles) {
            this.roles = roles;
        }
    }
}
