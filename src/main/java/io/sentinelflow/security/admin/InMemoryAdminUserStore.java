package io.sentinelflow.security.admin;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Collectors;

/**
 * In-memory admin user store backed by application configuration.
 * Suitable for development and small deployments.
 */
@Component
public class InMemoryAdminUserStore implements AdminUserStore {

    private static final Logger logger = LoggerFactory.getLogger(InMemoryAdminUserStore.class);

    private final Map<String, AdminPrincipal> users = new ConcurrentHashMap<>();
    private final PasswordEncoder passwordEncoder = new BCryptPasswordEncoder();

    public InMemoryAdminUserStore(AdminSecurityProperties properties) {
        for (AdminSecurityProperties.UserDefinition userDef : properties.getUsers()) {
            Set<AdminRole> roles = userDef.getRoles().stream()
                .map(role -> AdminRole.valueOf(role.toUpperCase()))
                .collect(Collectors.toSet());

            AdminPrincipal principal = new AdminPrincipal(
                userDef.getUsername(),
                roles,
                userDef.getPasswordHash()
            );
            users.put(userDef.getUsername(), principal);
            logger.info("Loaded admin user: {} with roles: {}", userDef.getUsername(), roles);
        }

        if (users.isEmpty()) {
            logger.warn("No admin users configured. Admin endpoints will be inaccessible.");
        }
    }

    @Override
    public Optional<AdminPrincipal> findByUsername(String username) {
        return Optional.ofNullable(users.get(username));
    }

    @Override
    public boolean validatePassword(String rawPassword, String encodedPassword) {
        return passwordEncoder.matches(rawPassword, encodedPassword);
    }
}
