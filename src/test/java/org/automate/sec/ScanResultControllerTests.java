package org.automate.sec;

import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

import static org.junit.jupiter.api.Assertions.assertEquals;

class ScanResultControllerTests {

    private final ScanResultController controller = new ScanResultController(
            new ScanResultStore(),
            "n8n-test-token",
            "client-test-key"
    );

    @Test
    void rejectsUnauthenticatedResultIngestion() {
        ResponseEntity<String> response = controller.receiveScanResult(null, "{}");
        assertEquals(HttpStatus.UNAUTHORIZED, response.getStatusCode());
    }

    @Test
    void rejectsUnauthenticatedResultRead() {
        ResponseEntity<String> response = controller.getLatestResult(null);
        assertEquals(HttpStatus.UNAUTHORIZED, response.getStatusCode());
    }

    @Test
    void storesAndReturnsAuthenticatedResult() {
        ResponseEntity<String> accepted =
                controller.receiveScanResult("n8n-test-token", "{\"risk\":\"demo\"}");
        ResponseEntity<String> fetched = controller.getLatestResult("client-test-key");

        assertEquals(HttpStatus.OK, accepted.getStatusCode());
        assertEquals(HttpStatus.OK, fetched.getStatusCode());
        assertEquals("{\"risk\":\"demo\"}", fetched.getBody());
    }
}
