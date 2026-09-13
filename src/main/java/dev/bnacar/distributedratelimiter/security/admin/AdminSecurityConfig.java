package dev.bnacar.distributedratelimiter.security.admin;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.source.ImmutableSecret;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.access.hierarchicalroles.RoleHierarchy;
import org.springframework.security.access.hierarchicalroles.RoleHierarchyImpl;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.jose.jws.MacAlgorithm;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.cors.CorsConfigurationSource;

import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;

/**
 * Spring Security configuration for admin authentication.
 * <p>
 * Secures /admin/** endpoints with JWT bearer token authentication
 * while keeping all other endpoints (API, metrics, swagger) open.
 */
@Configuration
@EnableWebSecurity
@EnableMethodSecurity
public class AdminSecurityConfig {

    private static final Logger logger = LoggerFactory.getLogger(AdminSecurityConfig.class);

    private final AdminSecurityProperties properties;
    private final CorsConfigurationSource corsConfigurationSource;

    public AdminSecurityConfig(AdminSecurityProperties properties,
                               CorsConfigurationSource corsConfigurationSource) {
        this.properties = properties;
        this.corsConfigurationSource = corsConfigurationSource;
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
            .cors(cors -> cors.configurationSource(corsConfigurationSource))
            .csrf(csrf -> csrf.disable())
            .sessionManagement(session -> session
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS))
            .authorizeHttpRequests(auth -> auth
                // Login endpoint is public
                .requestMatchers(HttpMethod.POST, "/admin/auth/token").permitAll()
                // All other admin endpoints require authentication
                .requestMatchers("/admin/**").authenticated()
                // Everything else is open (preserves existing behavior)
                .anyRequest().permitAll()
            )
            .oauth2ResourceServer(oauth2 -> oauth2
                .jwt(jwt -> jwt
                    .decoder(jwtDecoder())
                    .jwtAuthenticationConverter(jwtAuthenticationConverter())
                )
            );

        logger.info("Admin security configured with JWT authentication");
        return http.build();
    }

    @Bean
    public JwtDecoder jwtDecoder() {
        String signingKey = properties.getJwt().getSigningKey();
        if (signingKey == null || signingKey.isBlank()) {
            throw new IllegalStateException(
                "sentinel.security.admin.jwt.signing-key is required. " +
                "Set ADMIN_JWT_SIGNING_KEY environment variable.");
        }

        byte[] keyBytes = signingKey.getBytes(StandardCharsets.UTF_8);
        // Pad to 32 bytes minimum for HMAC-SHA256
        if (keyBytes.length < 32) {
            byte[] padded = new byte[32];
            System.arraycopy(keyBytes, 0, padded, 0, keyBytes.length);
            keyBytes = padded;
        }

        SecretKeySpec secretKey = new SecretKeySpec(keyBytes, "HmacSHA256");
        return NimbusJwtDecoder.withSecretKey(secretKey)
            .macAlgorithm(MacAlgorithm.HS256)
            .build();
    }

    @Bean
    public JwtAuthenticationConverter jwtAuthenticationConverter() {
        JwtGrantedAuthoritiesConverter grantedAuthoritiesConverter = new JwtGrantedAuthoritiesConverter();
        // Roles are stored in "roles" claim as ["VIEWER", "OPERATOR", etc.]
        grantedAuthoritiesConverter.setAuthoritiesClaimName("roles");
        grantedAuthoritiesConverter.setAuthorityPrefix("ROLE_");

        JwtAuthenticationConverter converter = new JwtAuthenticationConverter();
        converter.setJwtGrantedAuthoritiesConverter(grantedAuthoritiesConverter);
        return converter;
    }

    @Bean
    public RoleHierarchy roleHierarchy() {
        return RoleHierarchyImpl.fromHierarchy(
            "ROLE_SUPER_ADMIN > ROLE_OPERATOR\n" +
            "ROLE_OPERATOR > ROLE_VIEWER"
        );
    }
}
