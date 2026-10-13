package org.automate.sec;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.*;
import org.springframework.http.client.SimpleClientHttpRequestFactory;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.client.RestClientException;
import org.springframework.web.client.RestTemplate;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.Set;
import java.util.stream.Collectors;

@RestController
public class SendController {

    private static final Logger logger = LoggerFactory.getLogger(SendController.class);

    private final RestTemplate restTemplate;
    private final String n8nUrl;
    private final String n8nWebhookToken;
    private final String scanApiKey;
    private final Set<String> allowedTargets;

    public SendController(
            @Value("${n8n.webhook.url}") String n8nUrl,
            @Value("${n8n.webhook.token:}") String n8nWebhookToken,
            @Value("${scan.api.key:}") String scanApiKey,
            @Value("${scan.allowed.targets:}") String allowedTargets
    ) {
        SimpleClientHttpRequestFactory requestFactory = new SimpleClientHttpRequestFactory();
        requestFactory.setConnectTimeout(5_000);
        requestFactory.setReadTimeout(30_000);
        this.restTemplate = new RestTemplate(requestFactory);
        this.n8nUrl = n8nUrl;
        this.n8nWebhookToken = n8nWebhookToken;
        this.scanApiKey = scanApiKey;
        this.allowedTargets = Arrays.stream(allowedTargets.split(","))
                .map(String::trim)
                .filter(value -> !value.isBlank())
                .collect(Collectors.toUnmodifiableSet());
    }

    @PostMapping("/send")
    public ResponseEntity<String> send(
            @RequestHeader(value = "X-Scan-API-Key", required = false) String providedApiKey,
            @RequestBody RequestData data
    ) {
        if (scanApiKey.isBlank() || n8nWebhookToken.isBlank()) {
            logger.error("Scan API or n8n webhook authentication is not configured");
            return ResponseEntity.status(HttpStatus.SERVICE_UNAVAILABLE)
                    .body("Scan service is not configured");
        }

        if (!secureEquals(scanApiKey, providedApiKey)) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Unauthorized");
        }

        if (data == null || !isValidIpv4(data.getIpaddress()) || !isValidPort(data.getPort())) {
            return ResponseEntity.badRequest().body("Invalid target IP address or port");
        }

        if (!allowedTargets.contains(data.getIpaddress())) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN)
                    .body("Target is not in the configured allowlist");
        }

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        headers.set("X-N8N-Webhook-Token", n8nWebhookToken);
        HttpEntity<RequestData> request = new HttpEntity<>(data, headers);

        try {
            ResponseEntity<String> response = restTemplate.postForEntity(
                    n8nUrl,
                    request,
                    String.class
            );
            return ResponseEntity.status(response.getStatusCode())
                    .body("Scan request accepted");
        } catch (RestClientException e) {
            logger.error("Failed to forward scan request to n8n: {}", e.getMessage());
            return ResponseEntity.status(HttpStatus.BAD_GATEWAY)
                    .body("Unable to reach the scan orchestrator");
        }
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

    private boolean isValidPort(String value) {
        if (value == null || !value.matches("\\d{1,5}")) {
            return false;
        }
        int port = Integer.parseInt(value);
        return port >= 1 && port <= 65535;
    }

    private boolean isValidIpv4(String value) {
        if (value == null || !value.matches("\\d{1,3}(\\.\\d{1,3}){3}")) {
            return false;
        }
        String[] octets = value.split("\\.");
        for (String octet : octets) {
            int number = Integer.parseInt(octet);
            if (number < 0 || number > 255) {
                return false;
            }
        }
        return true;
    }
}
