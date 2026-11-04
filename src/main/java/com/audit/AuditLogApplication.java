package com.audit;

import com.audit.chain.BundleVerifierCli;
import io.swagger.v3.oas.annotations.OpenAPIDefinition;
import io.swagger.v3.oas.annotations.enums.SecuritySchemeType;
import io.swagger.v3.oas.annotations.info.Info;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.security.SecurityScheme;
import java.time.Clock;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;

@SpringBootApplication
@OpenAPIDefinition(info = @Info(title = "Tamper-Evident Audit Log", version = "1.0.0",
        description = "Append-only, hash-chained audit events. No update or delete API."),
        security = @SecurityRequirement(name = "basicAuth"))
@SecurityScheme(name = "basicAuth", type = SecuritySchemeType.HTTP, scheme = "basic")
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
