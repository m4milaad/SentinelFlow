package io.sentinelflow.security.admin;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

class AdminTokenServiceTest {

    private AdminTokenService tokenService;
    private AdminSecurityProperties properties;

    @BeforeEach
    void setUp() {
        properties = new AdminSecurityProperties();
        AdminSecurityProperties.Jwt jwt = new AdminSecurityProperties.Jwt();
        jwt.setSigningKey("test-signing-key-must-be-at-least-32-characters-long");
        jwt.setIssuer("traffic-sentinel");
        jwt.setAudience("admin-api");
        jwt.setTokenTtl(Duration.ofHours(1));
        properties.setJwt(jwt);

        tokenService = new AdminTokenService(properties);
    }

    @Test
    void issueToken_ValidPrincipal_ReturnsToken() {
        AdminPrincipal principal = new AdminPrincipal("ops", Set.of(AdminRole.OPERATOR), null);

        String token = tokenService.issueToken(principal);

        assertNotNull(token);
        assertFalse(token.isBlank());
        // JWT has 3 parts separated by dots
        assertEquals(3, token.split("\\.").length);
    }

    @Test
    void validateToken_ValidToken_ReturnsPrincipal() {
        AdminPrincipal original = new AdminPrincipal("ops", Set.of(AdminRole.OPERATOR), null);
        String token = tokenService.issueToken(original);

        AdminPrincipal validated = tokenService.validateToken(token);

        assertEquals("ops", validated.username());
        assertTrue(validated.roles().contains(AdminRole.OPERATOR));
    }

    @Test
    void validateToken_MultipleRoles_AllPreserved() {
        AdminPrincipal original = new AdminPrincipal(
            "admin", Set.of(AdminRole.SUPER_ADMIN, AdminRole.OPERATOR, AdminRole.VIEWER), null);
        String token = tokenService.issueToken(original);

        AdminPrincipal validated = tokenService.validateToken(token);

        assertEquals(3, validated.roles().size());
        assertTrue(validated.roles().contains(AdminRole.SUPER_ADMIN));
        assertTrue(validated.roles().contains(AdminRole.OPERATOR));
        assertTrue(validated.roles().contains(AdminRole.VIEWER));
    }

    @Test
    void validateToken_ExpiredToken_ThrowsException() {
        // Create service with very short TTL
        AdminSecurityProperties shortTtlProps = new AdminSecurityProperties();
        AdminSecurityProperties.Jwt jwt = new AdminSecurityProperties.Jwt();
        jwt.setSigningKey("test-signing-key-must-be-at-least-32-characters-long");
        jwt.setIssuer("traffic-sentinel");
        jwt.setAudience("admin-api");
        jwt.setTokenTtl(Duration.ofMillis(1)); // Expires almost immediately
        shortTtlProps.setJwt(jwt);

        AdminTokenService shortTtlService = new AdminTokenService(shortTtlProps);
        AdminPrincipal principal = new AdminPrincipal("ops", Set.of(AdminRole.OPERATOR), null);
        String token = shortTtlService.issueToken(principal);

        // Wait for expiry
        try {
            Thread.sleep(50);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }

        assertThrows(AdminTokenService.InvalidTokenException.class,
            () -> shortTtlService.validateToken(token));
    }

    @Test
    void validateToken_TamperedSignature_ThrowsException() {
        AdminPrincipal principal = new AdminPrincipal("ops", Set.of(AdminRole.OPERATOR), null);
        String token = tokenService.issueToken(principal);

        // Tamper with the signature (last part)
        String tamperedToken = token.substring(0, token.lastIndexOf('.') + 1) + "tampered";

        assertThrows(AdminTokenService.InvalidTokenException.class,
            () -> tokenService.validateToken(tamperedToken));
    }

    @Test
    void validateToken_WrongAudience_ThrowsException() {
        // Create service with different audience
        AdminSecurityProperties otherProps = new AdminSecurityProperties();
        AdminSecurityProperties.Jwt jwt = new AdminSecurityProperties.Jwt();
        jwt.setSigningKey("test-signing-key-must-be-at-least-32-characters-long");
        jwt.setIssuer("traffic-sentinel");
        jwt.setAudience("different-audience");
        jwt.setTokenTtl(Duration.ofHours(1));
        otherProps.setJwt(jwt);

        AdminTokenService otherService = new AdminTokenService(otherProps);
        AdminPrincipal principal = new AdminPrincipal("ops", Set.of(AdminRole.OPERATOR), null);
        String token = otherService.issueToken(principal);

        // Validate with the original service that expects "admin-api" audience
        assertThrows(AdminTokenService.InvalidTokenException.class,
            () -> tokenService.validateToken(token));
    }

    @Test
    void constructor_MissingSigningKey_ThrowsException() {
        AdminSecurityProperties noKeyProps = new AdminSecurityProperties();
        AdminSecurityProperties.Jwt jwt = new AdminSecurityProperties.Jwt();
        // No signing key set
        noKeyProps.setJwt(jwt);

        assertThrows(IllegalStateException.class,
            () -> new AdminTokenService(noKeyProps));
    }

    @Test
    void validateToken_GarbageInput_ThrowsException() {
        assertThrows(AdminTokenService.InvalidTokenException.class,
            () -> tokenService.validateToken("not.a.valid.jwt"));
    }
}
