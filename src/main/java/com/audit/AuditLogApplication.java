package com.audit;

import com.audit.chain.BundleVerifierCli;
import com.audit.chain.SigningKey;
import io.swagger.v3.oas.annotations.OpenAPIDefinition;
import io.swagger.v3.oas.annotations.enums.SecuritySchemeType;
import io.swagger.v3.oas.annotations.info.Info;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.security.SecurityScheme;
import java.time.Clock;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.scheduling.annotation.EnableScheduling;

@SpringBootApplication
@EnableScheduling
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

    /** Fails startup when the Ed25519 key pair is missing or mismatched. */
    @Bean
    SigningKey signingKey(@Value("${audit.signing.private-key:}") String privateKey,
                          @Value("${audit.signing.public-key:}") String publicKey) {
        return SigningKey.of(privateKey, publicKey);
    }
}
