package com.audit;

import com.audit.chain.BundleVerifierCli;
import java.time.Clock;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;

@SpringBootApplication
public class AuditLogApplication {

    /**
     * Starts the service, or with {@code verify-bundle <file>} runs the offline bundle verifier
     * without starting Spring.
     */
    public static void main(String[] args) {
        if (args.length > 0 && "verify-bundle".equals(args[0])) {
            System.exit(BundleVerifierCli.run(args));
        }
        SpringApplication.run(AuditLogApplication.class, args);
    }

    @Bean
    Clock clock() {
        return Clock.systemUTC();
    }
}
