package com.audit.security;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.time.Instant;
import java.util.Arrays;
import java.util.Base64;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

/**
 * Issues access tokens for LOCAL TESTING, standing in for an identity provider. In production
 * tokens come from the organisation's OIDC provider; this tool needs the dev private key.
 *
 * <pre>java -jar target/audit-log.jar issue-dev-token --key config/dev-jwt/private-key.pem \
 *     --sub alice --roles READER --scopes CLIENT_ACCOUNT:acc-1* [--minutes 15]</pre>
 */
public final class DevTokenCli {

    static final String DEV_ISSUER = "http://localhost:8080/dev-issuer";

    private DevTokenCli() {
    }

    public static int run(String[] args) {
        Map<String, String> opts = new HashMap<>();
        for (int i = 1; i + 1 < args.length; i += 2) {
            opts.put(args[i], args[i + 1]);
        }
        if (!opts.containsKey("--key") || !opts.containsKey("--sub") || !opts.containsKey("--roles")) {
            System.err.println("usage: issue-dev-token --key <private-key.pem> --sub <name> --roles R1,R2 "
                    + "[--scopes TYPE:ID*,...] [--minutes 15] [--issuer url] [--audience audit-log]");
            return 2;
        }
        try {
            System.out.println(token(Files.readString(Path.of(opts.get("--key"))), opts.get("--sub"),
                    List.of(opts.get("--roles").split(",")),
                    opts.containsKey("--scopes") ? List.of(opts.get("--scopes").split(",")) : List.of(),
                    Long.parseLong(opts.getOrDefault("--minutes", "15")),
                    opts.getOrDefault("--issuer", DEV_ISSUER), opts.getOrDefault("--audience", "audit-log")));
            return 0;
        } catch (IOException | GeneralSecurityException | JOSEException | IllegalArgumentException e) {
            System.err.println("cannot issue token: " + e.getMessage());
            return 2;
        }
    }

    /** RS256 token with the claims this service reads. */
    public static String token(String privateKeyPem, String subject, List<String> roles, List<String> scopes,
                               long minutes, String issuer, String audience)
            throws GeneralSecurityException, JOSEException {
        String body = privateKeyPem.replaceAll("-----(BEGIN|END) PRIVATE KEY-----", "").replaceAll("\\s", "");
        PrivateKey key = KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(Base64.getDecoder().decode(body)));
        Instant now = Instant.now();
        JWTClaimsSet.Builder claims = new JWTClaimsSet.Builder().issuer(issuer).audience(audience).subject(subject)
                .issueTime(Date.from(now)).notBeforeTime(Date.from(now))
                .expirationTime(Date.from(now.plusSeconds(minutes * 60))).jwtID(UUID.randomUUID().toString())
                .claim("roles", roles);
        if (!scopes.isEmpty()) {
            claims.claim("resource_scopes", scopes);
        }
        SignedJWT jwt = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.RS256).type(JOSEObjectType.JWT).build(),
                claims.build());
        jwt.sign(new RSASSASigner(key));
        return jwt.serialize();
    }

    static List<String> split(String csv) {
        return Arrays.stream(csv.split(",")).map(String::trim).filter(s -> !s.isEmpty()).toList();
    }
}
