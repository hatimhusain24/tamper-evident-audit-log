package com.audit.security;

import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtValidators;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;

/**
 * OAuth2 resource-server pieces: the JWT decoder with its validators, and the claim mapping.
 * Tokens must be RS256-signed by the configured issuer, carry this service's audience, have
 * exp/iat, and live no longer than the configured maximum. {@code sub} becomes the principal
 * (recorded as recordedBy), {@code roles} the authorities, {@code resource_scopes} the scopes.
 */
final class JwtSupport {

    private static final Duration CLOCK_SKEW = Duration.ofSeconds(60);

    private JwtSupport() {
    }

    static JwtDecoder decoder(AuditSecurityProperties.Jwt cfg) {
        if (blank(cfg.issuer())) {
            throw new IllegalStateException("audit.security.jwt.issuer is required in jwt mode. "
                    + "The service refuses to start without it.");
        }
        NimbusJwtDecoder decoder;
        if (!blank(cfg.publicKey())) {
            decoder = NimbusJwtDecoder.withPublicKey(rsaPublicKey(cfg.publicKey()))
                    .signatureAlgorithm(SignatureAlgorithm.RS256).build();
        } else if (!blank(cfg.jwkSetUri())) {
            decoder = NimbusJwtDecoder.withJwkSetUri(cfg.jwkSetUri()).jwsAlgorithm(SignatureAlgorithm.RS256).build();
        } else {
            throw new IllegalStateException("Set audit.security.jwt.jwk-set-uri (your identity provider's JWKS) "
                    + "or audit.security.jwt.public-key. The service refuses to start without a key source.");
        }
        decoder.setJwtValidator(new DelegatingOAuth2TokenValidator<>(
                JwtValidators.createDefaultWithIssuer(cfg.issuer()),        // exp, nbf (60 s skew) and iss
                audience(cfg.audience()),
                lifetime(Duration.ofMinutes(cfg.maxLifetimeMinutes()))));
        return decoder;
    }

    static JwtAuthenticationConverter converter() {
        JwtGrantedAuthoritiesConverter roles = new JwtGrantedAuthoritiesConverter();
        roles.setAuthoritiesClaimName("roles");
        roles.setAuthorityPrefix("ROLE_");
        JwtAuthenticationConverter converter = new JwtAuthenticationConverter();
        converter.setJwtGrantedAuthoritiesConverter(roles);
        converter.setPrincipalClaimName("sub");
        return converter;
    }

    private static OAuth2TokenValidator<Jwt> audience(String audience) {
        return jwt -> {
            java.util.List<String> aud = jwt.getAudience();
            return aud != null && aud.contains(audience)
                    ? OAuth2TokenValidatorResult.success()
                    : failure("token is not issued for audience " + audience);
        };
    }

    /**
     * Short-lived tokens only. exp is required, and must be at most maxLifetime after iat AND after
     * now. The second check matters: Spring fills a missing iat with exp - 1 s, so iat alone would
     * let a token without iat and a far-future exp through.
     */
    private static OAuth2TokenValidator<Jwt> lifetime(Duration max) {
        return jwt -> {
            Instant exp = jwt.getExpiresAt();
            Instant iat = jwt.getIssuedAt();
            if (exp == null) {
                return failure("token must have exp");
            }
            boolean issuedWindowOk = iat == null || Duration.between(iat, exp).compareTo(max) <= 0;
            boolean remainingOk = exp.isBefore(Instant.now().plus(max).plus(CLOCK_SKEW));
            return issuedWindowOk && remainingOk
                    ? OAuth2TokenValidatorResult.success()
                    : failure("token lifetime exceeds " + max.toMinutes() + " minutes");
        };
    }

    private static OAuth2TokenValidatorResult failure(String description) {
        return OAuth2TokenValidatorResult.failure(new OAuth2Error("invalid_token", description, null));
    }

    /** Accepts a PEM public key with or without the BEGIN/END lines. */
    static RSAPublicKey rsaPublicKey(String pem) {
        String body = pem.replaceAll("-----(BEGIN|END) PUBLIC KEY-----", "").replaceAll("\\s", "");
        try {
            return (RSAPublicKey) KeyFactory.getInstance("RSA")
                    .generatePublic(new X509EncodedKeySpec(Base64.getDecoder().decode(body)));
        } catch (GeneralSecurityException | IllegalArgumentException | ClassCastException e) {
            throw new IllegalStateException("audit.security.jwt.public-key is not a valid RSA public key", e);
        }
    }

    private static boolean blank(String s) {
        return s == null || s.isBlank();
    }
}
