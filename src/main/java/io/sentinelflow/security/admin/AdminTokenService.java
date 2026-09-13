package io.sentinelflow.security.admin;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.crypto.MACVerifier;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.text.ParseException;
import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Service for issuing and validating admin JWT tokens.
 * Uses HMAC-SHA256 signing with a locally configured secret key.
 */
@Service
public class AdminTokenService {

    private static final Logger logger = LoggerFactory.getLogger(AdminTokenService.class);

    private final AdminSecurityProperties properties;
    private final byte[] signingKeyBytes;

    public AdminTokenService(AdminSecurityProperties properties) {
        this.properties = properties;
        String signingKey = properties.getJwt().getSigningKey();
        if (signingKey == null || signingKey.isBlank()) {
            throw new IllegalStateException(
                "sentinel.security.admin.jwt.signing-key is required. " +
                "Set ADMIN_JWT_SIGNING_KEY environment variable.");
        }
        // Pad key to minimum 256 bits (32 bytes) for HMAC-SHA256
        byte[] rawBytes = signingKey.getBytes(java.nio.charset.StandardCharsets.UTF_8);
        if (rawBytes.length < 32) {
            byte[] padded = new byte[32];
            System.arraycopy(rawBytes, 0, padded, 0, rawBytes.length);
            this.signingKeyBytes = padded;
        } else {
            this.signingKeyBytes = rawBytes;
        }
    }

    /**
     * Issue a JWT token for an authenticated admin principal.
     *
     * @param principal the authenticated admin user
     * @return signed JWT string
     */
    public String issueToken(AdminPrincipal principal) {
        try {
            AdminSecurityProperties.Jwt jwtConfig = properties.getJwt();

            List<String> roleStrings = principal.roles().stream()
                .map(AdminRole::name)
                .collect(Collectors.toList());

            JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .subject(principal.username())
                .issuer(jwtConfig.getIssuer())
                .audience(jwtConfig.getAudience())
                .claim("roles", roleStrings)
                .issueTime(Date.from(Instant.now()))
                .expirationTime(Date.from(Instant.now().plus(jwtConfig.getTokenTtl())))
                .build();

            JWSHeader header = new JWSHeader(JWSAlgorithm.HS256);
            SignedJWT signedJWT = new SignedJWT(header, claims);

            JWSSigner signer = new MACSigner(signingKeyBytes);
            signedJWT.sign(signer);

            logger.debug("Issued JWT for user: {} with roles: {}", principal.username(), roleStrings);
            return signedJWT.serialize();

        } catch (JOSEException e) {
            logger.error("Failed to issue JWT for user: {}", principal.username(), e);
            throw new RuntimeException("Failed to issue JWT", e);
        }
    }

    /**
     * Validate a JWT token and extract the admin principal.
     *
     * @param token the JWT string
     * @return the admin principal from the token
     * @throws InvalidTokenException if the token is invalid, expired, or has wrong audience/issuer
     */
    public AdminPrincipal validateToken(String token) {
        try {
            SignedJWT signedJWT = SignedJWT.parse(token);
            AdminSecurityProperties.Jwt jwtConfig = properties.getJwt();

            // Verify signature
            JWSVerifier verifier = new MACVerifier(signingKeyBytes);
            if (!signedJWT.verify(verifier)) {
                throw new InvalidTokenException("Invalid token signature");
            }

            JWTClaimsSet claims = signedJWT.getJWTClaimsSet();

            // Verify expiration
            Date expiration = claims.getExpirationTime();
            if (expiration == null || expiration.before(new Date())) {
                throw new InvalidTokenException("Token has expired");
            }

            // Verify issuer
            String issuer = claims.getIssuer();
            if (!jwtConfig.getIssuer().equals(issuer)) {
                throw new InvalidTokenException("Invalid token issuer: " + issuer);
            }

            // Verify audience
            List<String> audience = claims.getAudience();
            if (audience == null || !audience.contains(jwtConfig.getAudience())) {
                throw new InvalidTokenException("Invalid token audience");
            }

            // Extract roles
            @SuppressWarnings("unchecked")
            List<String> roleStrings = (List<String>) claims.getClaim("roles");
            Set<AdminRole> roles = roleStrings.stream()
                .map(AdminRole::valueOf)
                .collect(Collectors.toSet());

            return AdminPrincipal.fromToken(claims.getSubject(), roles);

        } catch (ParseException | JOSEException e) {
            throw new InvalidTokenException("Failed to parse or verify token", e);
        }
    }

    /**
     * Exception thrown when a JWT token is invalid.
     */
    public static class InvalidTokenException extends RuntimeException {
        private static final long serialVersionUID = 1L;
        public InvalidTokenException(String message) {
            super(message);
        }

        public InvalidTokenException(String message, Throwable cause) {
            super(message, cause);
        }
    }
}
