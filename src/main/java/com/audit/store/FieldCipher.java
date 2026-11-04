package com.audit.store;

import com.audit.chain.HashChain;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Encrypts sensitive payload fields at rest with AES-256-GCM (random 96-bit IV per value). Hashes
 * and commitments are computed over the plaintext, so verification is unchanged; only the stored
 * bytes are ciphertext. Values are stored as {@code enc:v1:base64(iv || ciphertext+tag)}; that
 * prefix is reserved and refused on input.
 */
public final class FieldCipher {

    public static final String PREFIX = "enc:v1:";
    private static final int IV_BYTES = 12;
    private static final int TAG_BITS = 128;

    private final SecretKeySpec key;
    private final Set<String> fields;
    private final SecureRandom random = new SecureRandom();
    private final ObjectMapper json = new ObjectMapper();

    private FieldCipher(byte[] key, Set<String> fields) {
        this.key = new SecretKeySpec(key, "AES");
        this.fields = Set.copyOf(fields);
    }

    /** Refuses a missing or wrong-size key, so sensitive data is never written in plaintext. */
    public static FieldCipher of(String keyBase64, Set<String> sensitiveFields) {
        byte[] key;
        try {
            key = keyBase64 == null ? new byte[0] : Base64.getDecoder().decode(keyBase64.trim());
        } catch (IllegalArgumentException e) {
            key = new byte[0];
        }
        if (key.length != 32) {
            throw new IllegalStateException("audit.encryption-key (AUDIT_ENCRYPTION_KEY) must be 32 bytes, base64. "
                    + "The service refuses to start without it.");
        }
        return new FieldCipher(key, sensitiveFields);
    }

    /** Copy of the payload with sensitive values encrypted (redacted markers stay readable). */
    public Map<String, Object> encrypt(Map<String, Object> payload) {
        Map<String, Object> out = new LinkedHashMap<>(payload);
        out.replaceAll((k, v) -> fields.contains(k) && v != null && !HashChain.REDACTED.equals(v) ? seal(v) : v);
        return out;
    }

    /** Copy of the payload with every encrypted value restored; null if any value fails to decrypt. */
    public Map<String, Object> decrypt(Map<String, Object> stored) {
        Map<String, Object> out = new LinkedHashMap<>(stored);
        for (Map.Entry<String, Object> e : out.entrySet()) {
            if (e.getValue() instanceof String s && s.startsWith(PREFIX)) {
                Object plain = open(s);
                if (plain == UNREADABLE) {
                    return null;   // wrong key or tampered ciphertext: reported as CORRUPT_RECORD
                }
                e.setValue(plain);
            }
        }
        return out;
    }

    private static final Object UNREADABLE = new Object();

    private String seal(Object value) {
        try {
            byte[] iv = new byte[IV_BYTES];
            random.nextBytes(iv);
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(TAG_BITS, iv));
            byte[] sealed = cipher.doFinal(HashChain.canonical(value));
            byte[] out = new byte[IV_BYTES + sealed.length];
            System.arraycopy(iv, 0, out, 0, IV_BYTES);
            System.arraycopy(sealed, 0, out, IV_BYTES, sealed.length);
            return PREFIX + Base64.getEncoder().encodeToString(out);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("AES/GCM is required by every JVM", e);
        }
    }

    private Object open(String stored) {
        try {
            byte[] in = Base64.getDecoder().decode(stored.substring(PREFIX.length()));
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(TAG_BITS, in, 0, IV_BYTES));
            return json.readValue(cipher.doFinal(in, IV_BYTES, in.length - IV_BYTES), Object.class);
        } catch (GeneralSecurityException | IllegalArgumentException | IOException e) {
            return UNREADABLE;
        }
    }
}
