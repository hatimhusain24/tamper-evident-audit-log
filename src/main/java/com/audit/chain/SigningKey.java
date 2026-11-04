package com.audit.chain;

import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

/**
 * Ed25519 key pair used to sign export bundles and checkpoints. Anyone holding the public key can
 * check a signature offline; only the service can create one. Keys come from config (PKCS#8 and
 * X.509, base64), in production from a secret manager.
 */
public final class SigningKey {

    public static final String ALGORITHM = "Ed25519";
    private final PrivateKey privateKey;
    private final String publicKeyBase64;

    private SigningKey(PrivateKey privateKey, String publicKeyBase64) {
        this.privateKey = privateKey;
        this.publicKeyBase64 = publicKeyBase64;
    }

    /** Refuses missing, malformed or mismatched keys, so the service never signs with a wrong key. */
    public static SigningKey of(String privateBase64, String publicBase64) {
        if (privateBase64 == null || privateBase64.isBlank() || publicBase64 == null || publicBase64.isBlank()) {
            throw new IllegalStateException("audit.signing.private-key and audit.signing.public-key are required. "
                    + "The service refuses to start without them.");
        }
        try {
            KeyFactory factory = KeyFactory.getInstance(ALGORITHM);
            PrivateKey key = factory.generatePrivate(new PKCS8EncodedKeySpec(Base64.getDecoder().decode(privateBase64)));
            SigningKey signing = new SigningKey(key, publicBase64);
            byte[] probe = "key-pair-check".getBytes(java.nio.charset.StandardCharsets.UTF_8);
            if (!verify(publicBase64, probe, signing.sign(probe))) {
                throw new IllegalStateException("audit.signing public key does not match the private key");
            }
            return signing;
        } catch (GeneralSecurityException | IllegalArgumentException e) {
            throw new IllegalStateException("audit.signing keys are not valid Ed25519 keys", e);
        }
    }

    public String publicKeyBase64() {
        return publicKeyBase64;
    }

    public String sign(byte[] data) {
        try {
            Signature signer = Signature.getInstance(ALGORITHM);
            signer.initSign(privateKey);
            signer.update(data);
            return Base64.getEncoder().encodeToString(signer.sign());
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("Ed25519 is required by every JDK 15+", e);
        }
    }

    /** Offline check: true only if {@code signatureBase64} is a valid signature of data by this public key. */
    public static boolean verify(String publicBase64, byte[] data, String signatureBase64) {
        if (publicBase64 == null || signatureBase64 == null) {
            return false;
        }
        try {
            PublicKey key = KeyFactory.getInstance(ALGORITHM)
                    .generatePublic(new X509EncodedKeySpec(Base64.getDecoder().decode(publicBase64)));
            Signature verifier = Signature.getInstance(ALGORITHM);
            verifier.initVerify(key);
            verifier.update(data);
            return verifier.verify(Base64.getDecoder().decode(signatureBase64));
        } catch (GeneralSecurityException | IllegalArgumentException e) {
            return false;
        }
    }
}
