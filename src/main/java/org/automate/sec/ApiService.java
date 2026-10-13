package org.automate.sec;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.http.client.SimpleClientHttpRequestFactory;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestClientException;
import org.springframework.web.client.RestTemplate;

@Service
public class ApiService {

    private static final Logger logger = LoggerFactory.getLogger(ApiService.class);

    private final RestTemplate restTemplate;

    @Value("${api.url:http://localhost:5000/api}")
    private String url;

    public ApiService() {
        SimpleClientHttpRequestFactory requestFactory = new SimpleClientHttpRequestFactory();
        requestFactory.setConnectTimeout(5_000);
        requestFactory.setReadTimeout(30_000);
        this.restTemplate = new RestTemplate(requestFactory);
    }

    public String sendRequest() {
        RequestData data = new RequestData("192.168.1.10", "8080");

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        HttpEntity<RequestData> request = new HttpEntity<>(data, headers);

        try {
            ResponseEntity<String> response = restTemplate.postForEntity(
                    url,
                    request,
                    String.class
            );
            return response.getBody();
        } catch (RestClientException e) {
            logger.error("Failed to send request to {}: {}", url, e.getMessage());
            return "Request failed";
        }
    }
}
