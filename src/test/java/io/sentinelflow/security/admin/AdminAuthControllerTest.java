package io.sentinelflow.security.admin;

import tools.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import java.util.Map;
import java.util.Set;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT, properties = {
    "ratelimiter.geographic.enabled=false"
})
@AutoConfigureMockMvc
class AdminAuthControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @Autowired
    private AdminTokenService tokenService;

    @Test
    void login_ValidCredentials_ReturnsToken() throws Exception {
        String requestBody = objectMapper.writeValueAsString(
            Map.of("username", "ops", "password", "changeme"));

        mockMvc.perform(post("/admin/auth/token")
                .contentType(MediaType.APPLICATION_JSON)
                .content(requestBody))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.token").isNotEmpty())
                .andExpect(jsonPath("$.type").value("Bearer"));
    }

    @Test
    void login_BadPassword_ReturnsUnauthorized() throws Exception {
        String requestBody = objectMapper.writeValueAsString(
            Map.of("username", "ops", "password", "wrongpassword"));

        mockMvc.perform(post("/admin/auth/token")
                .contentType(MediaType.APPLICATION_JSON)
                .content(requestBody))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.error").value("Invalid credentials"));
    }

    @Test
    void login_UnknownUser_ReturnsUnauthorized() throws Exception {
        String requestBody = objectMapper.writeValueAsString(
            Map.of("username", "nobody", "password", "changeme"));

        mockMvc.perform(post("/admin/auth/token")
                .contentType(MediaType.APPLICATION_JSON)
                .content(requestBody))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void whoami_WithValidToken_ReturnsPrincipal() throws Exception {
        AdminPrincipal principal = new AdminPrincipal("ops", Set.of(AdminRole.OPERATOR), null);
        String token = tokenService.issueToken(principal);

        mockMvc.perform(get("/admin/auth/whoami")
                .header("Authorization", "Bearer " + token))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.username").value("ops"))
                .andExpect(jsonPath("$.roles").isArray());
    }

    @Test
    void whoami_WithoutToken_ReturnsUnauthorized() throws Exception {
        mockMvc.perform(get("/admin/auth/whoami"))
                .andExpect(status().isUnauthorized());
    }
}
