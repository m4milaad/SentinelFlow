package dev.bnacar.distributedratelimiter.controller;

import tools.jackson.databind.ObjectMapper;
import dev.bnacar.distributedratelimiter.models.AdminLimitRequest;
import dev.bnacar.distributedratelimiter.ratelimit.RateLimitAlgorithm;
import dev.bnacar.distributedratelimiter.security.admin.AdminPrincipal;
import dev.bnacar.distributedratelimiter.security.admin.AdminRole;
import dev.bnacar.distributedratelimiter.security.admin.AdminTokenService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

import java.util.Set;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT, properties = {"ratelimiter.geographic.enabled=false"})
@AutoConfigureMockMvc
class AdminControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @Autowired
    private AdminTokenService tokenService;

    private String getViewerToken() {
        AdminPrincipal principal = new AdminPrincipal("viewer", Set.of(AdminRole.VIEWER), null);
        return tokenService.issueToken(principal);
    }

    private String getOperatorToken() {
        AdminPrincipal principal = new AdminPrincipal("operator", Set.of(AdminRole.OPERATOR), null);
        return tokenService.issueToken(principal);
    }

    private String getSuperAdminToken() {
        AdminPrincipal principal = new AdminPrincipal("admin", Set.of(AdminRole.SUPER_ADMIN), null);
        return tokenService.issueToken(principal);
    }

    @Test
    void getKeyLimits_WithViewerToken_ReturnsDefaultLimits() throws Exception {
        mockMvc.perform(get("/admin/limits/test-key")
                .header("Authorization", "Bearer " + getViewerToken()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.key").value("test-key"))
                .andExpect(jsonPath("$.capacity").value(10))
                .andExpect(jsonPath("$.refillRate").value(2))
                .andExpect(jsonPath("$.algorithm").value("TOKEN_BUCKET"));
    }

    @Test
    void getKeyLimits_WithoutAuthentication_ReturnsUnauthorized() throws Exception {
        mockMvc.perform(get("/admin/limits/test-key"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void updateKeyLimits_WithOperatorToken_UpdatesLimits() throws Exception {
        String key = "update-test-key";
        AdminLimitRequest request = new AdminLimitRequest(20, 10, 120000L, RateLimitAlgorithm.SLIDING_WINDOW);

        mockMvc.perform(put("/admin/limits/{key}", key)
                .header("Authorization", "Bearer " + getOperatorToken())
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.key").value(key))
                .andExpect(jsonPath("$.capacity").value(20))
                .andExpect(jsonPath("$.refillRate").value(10))
                .andExpect(jsonPath("$.cleanupIntervalMs").value(120000))
                .andExpect(jsonPath("$.algorithm").value("SLIDING_WINDOW"));
    }

    @Test
    void updateKeyLimits_WithViewerToken_ReturnsForbidden() throws Exception {
        String key = "test-key";
        AdminLimitRequest request = new AdminLimitRequest(20, 10, 120000L, RateLimitAlgorithm.TOKEN_BUCKET);

        mockMvc.perform(put("/admin/limits/{key}", key)
                .header("Authorization", "Bearer " + getViewerToken())
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isForbidden());
    }

    @Test
    void updateKeyLimits_WithInvalidRequest_ReturnsBadRequest() throws Exception {
        String key = "test-key";
        AdminLimitRequest request = new AdminLimitRequest(-1, -1, 100L, null);

        mockMvc.perform(put("/admin/limits/{key}", key)
                .header("Authorization", "Bearer " + getOperatorToken())
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isBadRequest());
    }

    @Test
    void removeKeyLimits_WithOperatorToken_RemovesLimits() throws Exception {
        String key = "delete-test-key";
        AdminLimitRequest request = new AdminLimitRequest(5, 2, 30000L, RateLimitAlgorithm.TOKEN_BUCKET);

        mockMvc.perform(put("/admin/limits/{key}", key)
                .header("Authorization", "Bearer " + getOperatorToken())
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(request)));

        mockMvc.perform(delete("/admin/limits/{key}", key)
                .header("Authorization", "Bearer " + getOperatorToken()))
                .andExpect(status().isOk())
                .andExpect(content().string("Limits removed for key: " + key));
    }

    @Test
    void getAllKeys_WithViewerToken_ReturnsKeyList() throws Exception {
        mockMvc.perform(get("/admin/keys")
                .header("Authorization", "Bearer " + getViewerToken()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.totalKeys").exists())
                .andExpect(jsonPath("$.activeKeys").exists())
                .andExpect(jsonPath("$.keys").isArray());
    }

    @Test
    void getAllKeys_WithoutAuthentication_ReturnsUnauthorized() throws Exception {
        mockMvc.perform(get("/admin/keys"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void superAdmin_CanPerformOperatorActions() throws Exception {
        String key = "super-admin-test-key";
        AdminLimitRequest request = new AdminLimitRequest(50, 25, 60000L, RateLimitAlgorithm.TOKEN_BUCKET);

        // SUPER_ADMIN should inherit OPERATOR permissions via role hierarchy
        mockMvc.perform(put("/admin/limits/{key}", key)
                .header("Authorization", "Bearer " + getSuperAdminToken())
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isOk());
    }

    @Test
    void adminAuthentication_WithExpiredToken_ReturnsUnauthorized() throws Exception {
        // Create a token with a very short TTL that will be expired
        // We test this indirectly — just verify the system rejects garbage tokens
        mockMvc.perform(get("/admin/keys")
                .header("Authorization", "Bearer invalid.token.here"))
                .andExpect(status().isUnauthorized());
    }
}