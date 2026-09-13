package io.sentinelflow.security.abuse;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.Map;

/**
 * Admin endpoints for abuse mitigation management.
 * Requires appropriate admin roles (via Feature 1 JWT auth).
 */
@RestController
@RequestMapping("/admin/abuse")
@Tag(name = "abuse-mitigation", description = "Abuse detection and mitigation management")
public class AbuseMitigationController {

    private final BlockedKeyStore blockedKeyStore;
    private final AbuseAuditLog auditLog;

    public AbuseMitigationController(BlockedKeyStore blockedKeyStore, AbuseAuditLog auditLog) {
        this.blockedKeyStore = blockedKeyStore;
        this.auditLog = auditLog;
    }

    /**
     * List all currently blocked keys.
     */
    @GetMapping("/blocked")
    @PreAuthorize("hasRole('VIEWER')")
    @Operation(summary = "List blocked keys", description = "Returns all currently blocked rate limit keys")
    @ApiResponse(responseCode = "200", description = "Blocked keys retrieved")
    public ResponseEntity<Map<String, Object>> getBlockedKeys() {
        List<BlockedKeyStore.BlockedKeyInfo> blocked = blockedKeyStore.getBlockedKeys();
        return ResponseEntity.ok(Map.of(
            "blockedKeys", blocked,
            "total", blocked.size()
        ));
    }

    /**
     * Manually unblock a key.
     */
    @PostMapping("/unblock/{key}")
    @PreAuthorize("hasRole('OPERATOR')")
    @Operation(summary = "Unblock a key", description = "Manually remove a key from the block list")
    @ApiResponse(responseCode = "200", description = "Key unblocked")
    public ResponseEntity<Map<String, String>> unblockKey(
            @Parameter(description = "The blocked key to unblock", required = true)
            @PathVariable("key") String key) {
        blockedKeyStore.unblockKey(key);
        return ResponseEntity.ok(Map.of(
            "message", "Key unblocked: " + key,
            "key", key
        ));
    }

    /**
     * Get paginated audit trail of mitigation actions.
     */
    @GetMapping("/audit")
    @PreAuthorize("hasRole('VIEWER')")
    @Operation(summary = "Get audit trail", description = "Paginated log of all abuse mitigation actions")
    @ApiResponse(responseCode = "200", description = "Audit entries retrieved")
    public ResponseEntity<Map<String, Object>> getAuditTrail(
            @Parameter(description = "Page number (0-based)")
            @RequestParam(defaultValue = "0") int page,
            @Parameter(description = "Page size")
            @RequestParam(defaultValue = "20") int size) {

        List<AbuseAuditLog.AuditEntry> entries = auditLog.getEntries(page, size);
        int totalEntries = auditLog.getTotalEntries();

        return ResponseEntity.ok(Map.of(
            "entries", entries,
            "page", page,
            "size", size,
            "totalEntries", totalEntries,
            "totalPages", (int) Math.ceil((double) totalEntries / size)
        ));
    }
}
