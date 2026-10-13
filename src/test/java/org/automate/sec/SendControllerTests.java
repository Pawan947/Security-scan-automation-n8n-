package org.automate.sec;

import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

import static org.junit.jupiter.api.Assertions.assertEquals;

class SendControllerTests {

    private final SendController controller = new SendController(
            "http://127.0.0.1:1/webhook",
            "n8n-test-token",
            "client-test-key",
            "192.168.1.10"
    );

    @Test
    void rejectsMissingApiKey() {
        ResponseEntity<String> response =
                controller.send(null, new RequestData("192.168.1.10", "443"));

        assertEquals(HttpStatus.UNAUTHORIZED, response.getStatusCode());
    }

    @Test
    void rejectsMalformedIpAddress() {
        ResponseEntity<String> response =
                controller.send("client-test-key", new RequestData("192.168.1.999", "443"));

        assertEquals(HttpStatus.BAD_REQUEST, response.getStatusCode());
    }

    @Test
    void rejectsOutOfRangePort() {
        ResponseEntity<String> response =
                controller.send("client-test-key", new RequestData("192.168.1.10", "70000"));

        assertEquals(HttpStatus.BAD_REQUEST, response.getStatusCode());
    }

    @Test
    void rejectsTargetOutsideAllowlist() {
        ResponseEntity<String> response =
                controller.send("client-test-key", new RequestData("192.168.1.11", "443"));

        assertEquals(HttpStatus.FORBIDDEN, response.getStatusCode());
    }

    @Test
    void rejectsMissingTargetData() {
        ResponseEntity<String> response =
                controller.send("client-test-key", new RequestData());

        assertEquals(HttpStatus.BAD_REQUEST, response.getStatusCode());
    }
}
