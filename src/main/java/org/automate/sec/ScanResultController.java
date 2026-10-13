package org.automate.sec;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;

@RestController
@RequestMapping("/api/scan-results")
public class ScanResultController {

    private static final Logger logger = LoggerFactory.getLogger(ScanResultController.class);

    private final ScanResultStore store;
    private final String n8nWebhookToken;
    private final String scanApiKey;

    public ScanResultController(
            ScanResultStore store,
            @Value("${n8n.webhook.token:}") String n8nWebhookToken,
            @Value("${scan.api.key:}") String scanApiKey
    ) {
        this.store = store;
        this.n8nWebhookToken = n8nWebhookToken;
        this.scanApiKey = scanApiKey;
    }

    @PostMapping
    public ResponseEntity<String> receiveScanResult(
            @RequestHeader(value = "X-N8N-Webhook-Token", required = false) String providedToken,
            @RequestBody String body
    ) {
        if (n8nWebhookToken.isBlank()) {
            return ResponseEntity.status(HttpStatus.SERVICE_UNAVAILABLE)
                    .body("Result ingestion is not configured");
        }
        if (!secureEquals(n8nWebhookToken, providedToken)) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Unauthorized");
        }

        logger.info("Received authenticated scan result from n8n");
        store.setLatestResult(body);
        return ResponseEntity.ok()
                .header("Content-Type", "application/json")
                .body("{\"status\":\"success\",\"message\":\"Scan result received\"}");
    }

    @GetMapping("/latest")
    public ResponseEntity<String> getLatestResult(
            @RequestHeader(value = "X-Scan-API-Key", required = false) String providedApiKey
    ) {
        if (scanApiKey.isBlank()) {
            return ResponseEntity.status(HttpStatus.SERVICE_UNAVAILABLE).build();
        }
        if (!secureEquals(scanApiKey, providedApiKey)) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }

        String result = store.getLatestResult();
        if (result == null) {
            return ResponseEntity.noContent().build();
        }
        return ResponseEntity.ok()
                .header("Content-Type", "application/json")
                .body(result);
    }

    private boolean secureEquals(String expected, String provided) {
        if (provided == null) {
            return false;
        }
        return MessageDigest.isEqual(
                expected.getBytes(StandardCharsets.UTF_8),
                provided.getBytes(StandardCharsets.UTF_8)
        );
    }
}
