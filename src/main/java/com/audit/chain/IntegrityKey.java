package com.audit.chain;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.HexFormat;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * Server-side secret for record MACs. A DB admin can recompute plain SHA-256 hashes (the
 * algorithm is public) but cannot produce valid MACs without this key, so a full chain rewrite
 * is detected. In production the key comes from a secret manager / KMS via AUDIT_HMAC_KEY.
 */
public final class IntegrityKey {

    static final int MIN_BYTES = 32;
    private final byte[] key;

    private IntegrityKey(byte[] key) {
        this.key = key;
    }

    /** Refuses missing or short keys, so the service can't run with forgeable MACs. */
    public static IntegrityKey of(String secret) {
        if (secret == null || secret.getBytes(StandardCharsets.UTF_8).length < MIN_BYTES) {
            throw new IllegalStateException("audit.hmac-key (AUDIT_HMAC_KEY) must be at least "
                    + MIN_BYTES + " bytes. The service refuses to start without it.");
        }
        return new IntegrityKey(secret.getBytes(StandardCharsets.UTF_8));
    }

    public String mac(String recordHash) {
        try {
            Mac hmac = Mac.getInstance("HmacSHA256");
            hmac.init(new SecretKeySpec(key, "HmacSHA256"));
            return HexFormat.of().formatHex(hmac.doFinal(recordHash.getBytes(StandardCharsets.UTF_8)));
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("HmacSHA256 is required by every JVM", e);
        }
    }
}
