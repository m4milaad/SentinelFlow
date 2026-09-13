package io.sentinelflow.security.admin;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * Controller for admin authentication operations.
 */
@RestController
@RequestMapping("/admin/auth")
public class AdminAuthController {

    private static final Logger logger = LoggerFactory.getLogger(AdminAuthController.class);

    private final AdminTokenService tokenService;
    private final AdminUserStore userStore;

    public AdminAuthController(AdminTokenService tokenService, AdminUserStore userStore) {
        this.tokenService = tokenService;
        this.userStore = userStore;
    }

    /**
     * Exchange credentials for a JWT token.
     * This endpoint is public (no authentication required).
     */
    @PostMapping("/token")
    public ResponseEntity<Map<String, Object>> login(@RequestBody LoginRequest request) {
        Optional<AdminPrincipal> principalOpt = userStore.findByUsername(request.username());

        if (principalOpt.isEmpty()) {
            logger.warn("Login attempt for unknown user: {}", request.username());
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                .body(Map.of("error", "Invalid credentials"));
        }

        AdminPrincipal principal = principalOpt.get();

        if (!userStore.validatePassword(request.password(), principal.passwordHash())) {
            logger.warn("Failed login attempt for user: {}", request.username());
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                .body(Map.of("error", "Invalid credentials"));
        }

        String token = tokenService.issueToken(principal);
        logger.info("Successful login for user: {}", request.username());

        return ResponseEntity.ok(Map.of(
            "token", token,
            "type", "Bearer"
        ));
    }

    /**
     * Introspect the current authentication — debugging endpoint.
     */
    @GetMapping("/whoami")
    @PreAuthorize("isAuthenticated()")
    public ResponseEntity<Map<String, Object>> whoami(@AuthenticationPrincipal Jwt jwt) {
        @SuppressWarnings("unchecked")
        List<String> roles = (List<String>) jwt.getClaim("roles");

        return ResponseEntity.ok(Map.of(
            "username", jwt.getSubject(),
            "roles", roles != null ? roles : List.of(),
            "issuer", jwt.getClaimAsString("iss") != null ? jwt.getClaimAsString("iss") : "",
            "expiresAt", jwt.getExpiresAt() != null ? jwt.getExpiresAt().toString() : ""
        ));
    }

    /**
     * Login request payload.
     */
    public record LoginRequest(String username, String password) {}
}
