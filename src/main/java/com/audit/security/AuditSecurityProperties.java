package com.audit.security;

import java.time.Instant;
import java.util.List;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;

/**
 * Authentication settings.
 *
 * <ul>
 *   <li>{@code auth-mode=jwt} (production default): OAuth2 access tokens (JWT) issued by an OIDC
 *       identity provider such as Keycloak, Okta or Entra ID. Needs {@code jwt.issuer} and
 *       {@code jwt.jwk-set-uri} (or {@code jwt.public-key}).</li>
 *   <li>{@code auth-mode=basic}: configured users with bcrypt password hashes.</li>
 *   <li>{@code auth-mode=both}: either (local development and tests).</li>
 * </ul>
 *
 * <pre>
 * audit.security.users[0].name=ingest-service
 * audit.security.users[0].password-hash={bcrypt}$2a$10$...
 * audit.security.users[0].roles=WRITER
 * audit.security.users[0].resource-scopes=CLIENT_ACCOUNT:acc-1*        (optional; required for READER)
 * audit.security.users[0].password-expires-at=2027-01-01T00:00:00Z     (optional)
 * </pre>
 */
@ConfigurationProperties("audit.security")
public record AuditSecurityProperties(@DefaultValue("jwt") String authMode, List<ApiUser> users,
                                      @DefaultValue Jwt jwt) {

    public record ApiUser(String name, String passwordHash, List<String> roles, List<String> resourceScopes,
                          Instant passwordExpiresAt) {
    }

    /** Token validation: issuer, audience, signing keys and the longest token lifetime accepted. */
    public record Jwt(String issuer, @DefaultValue("audit-log") String audience, String jwkSetUri, String publicKey,
                      @DefaultValue("60") long maxLifetimeMinutes) {
    }

    public boolean basicEnabled() {
        return "basic".equals(authMode) || "both".equals(authMode);
    }

    public boolean jwtEnabled() {
        return "jwt".equals(authMode) || "both".equals(authMode);
    }

    /** Refuses unknown modes: there is no configuration that silently disables authentication. */
    public void validate() {
        if (!basicEnabled() && !jwtEnabled()) {
            throw new IllegalStateException("audit.security.auth-mode must be jwt, basic or both (was " + authMode + ")");
        }
    }
}
