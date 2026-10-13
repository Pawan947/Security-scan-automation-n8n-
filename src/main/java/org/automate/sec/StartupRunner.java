package org.automate.sec;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Component;

@Component
@ConditionalOnProperty(
        name = "app.startup-request.enabled",
        havingValue = "true"
)
public class StartupRunner implements CommandLineRunner {

    private static final Logger logger = LoggerFactory.getLogger(StartupRunner.class);

    private final ApiService apiService;

    public StartupRunner(ApiService apiService) {
        this.apiService = apiService;
    }

    @Override
    public void run(String... args) {
        try {
            String response = apiService.sendRequest();
            logger.info("Startup API response: {}", response);
        } catch (Exception e) {
            logger.error("Error executing startup runner: {}", e.getMessage(), e);
        }
    }
}
