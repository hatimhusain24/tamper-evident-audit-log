package com.audit.chain;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.util.HashMap;
import java.util.HexFormat;
import java.util.Map;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * Server-side keys for record MACs. A DB admin can recompute plain SHA-256 hashes (the algorithm
 * is public) but cannot produce valid MACs without a key, so a full chain rewrite is detected.
 *
 * <p>Rotation: each MAC is stored as {@code keyId:hex}. New records use the current key; retired
 * keys are kept only to verify records they signed. In production keys come from a secret
 * manager / KMS.
 */
public final class IntegrityKey {

    static final int MIN_BYTES = 32;
    private static final String ID_PATTERN = "[A-Za-z0-9_-]{1,16}";

    private final String currentId;
    private final Map<String, byte[]> keys;

    private IntegrityKey(String currentId, Map<String, byte[]> keys) {
        this.currentId = currentId;
        this.keys = Map.copyOf(keys);
    }

    /** Single key with id "k1". */
    public static IntegrityKey of(String secret) {
        return of("k1", secret, "");
    }

    /**
     * @param retired comma list of {@code id=secret} pairs that may verify but never sign
     * @throws IllegalStateException for missing or short secrets, bad or duplicate ids, so the
     *         service refuses to start with forgeable MACs
     */
    public static IntegrityKey of(String currentId, String currentSecret, String retired) {
        Map<String, byte[]> keys = new HashMap<>();
        keys.put(checkId(currentId), checkSecret(currentId, currentSecret));
        if (retired != null && !retired.isBlank()) {
            for (String pair : retired.split(",")) {
                String[] idSecret = pair.trim().split("=", 2);
                String id = checkId(idSecret[0]);
                if (keys.put(id, checkSecret(id, idSecret.length > 1 ? idSecret[1] : null)) != null) {
                    throw new IllegalStateException("duplicate HMAC key id " + id);
                }
            }
        }
        return new IntegrityKey(currentId, keys);
    }

    private static String checkId(String id) {
        if (id == null || !id.matches(ID_PATTERN)) {
            throw new IllegalStateException("HMAC key id must match " + ID_PATTERN);
        }
        return id;
    }

    private static byte[] checkSecret(String id, String secret) {
        if (secret == null || secret.getBytes(StandardCharsets.UTF_8).length < MIN_BYTES) {
            throw new IllegalStateException("HMAC key '" + id + "' (AUDIT_HMAC_KEY) must be at least "
                    + MIN_BYTES + " bytes. The service refuses to start without it.");
        }
        return secret.getBytes(StandardCharsets.UTF_8);
    }

    /** MAC with the current key, as {@code keyId:hex}. */
    public String mac(String recordHash) {
        return currentId + ":" + hmac(keys.get(currentId), recordHash);
    }

    /** Constant-time check against whichever known key the stored MAC names. */
    public boolean matches(String recordHash, String storedMac) {
        if (recordHash == null || storedMac == null || storedMac.indexOf(':') < 0) {
            return false;
        }
        String id = storedMac.substring(0, storedMac.indexOf(':'));
        byte[] key = keys.get(id);
        if (key == null) {
            return false;   // unknown or removed key id
        }
        String expected = id + ":" + hmac(key, recordHash);
        return MessageDigest.isEqual(expected.getBytes(StandardCharsets.UTF_8), storedMac.getBytes(StandardCharsets.UTF_8));
    }

    private static String hmac(byte[] key, String data) {
        try {
            Mac hmac = Mac.getInstance("HmacSHA256");
            hmac.init(new SecretKeySpec(key, "HmacSHA256"));
            return HexFormat.of().formatHex(hmac.doFinal(data.getBytes(StandardCharsets.UTF_8)));
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("HmacSHA256 is required by every JVM", e);
        }
    }
}
