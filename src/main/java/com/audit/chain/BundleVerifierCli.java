package com.audit.chain;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.nio.file.Path;

/**
 * Offline verifier for export bundles: no server or database needed.
 *
 * <pre>java -jar target/audit-log.jar verify-bundle bundle.json [--head HASH] [--public-key BASE64]</pre>
 * {@code --head}: a trusted head hash (e.g. an anchored checkpoint). {@code --public-key}: the
 * service's Ed25519 key from GET /v1/audit/signing-key; then a missing, edited or dropped record
 * fails the signature. Exit code 0 = verified, 1 = verification failed, 2 = usage or read error.
 */
public final class BundleVerifierCli {

    private BundleVerifierCli() {
    }

    public static int run(String[] args) {
        String head = null;
        String publicKey = null;
        for (int i = 2; i < args.length; i++) {
            if ("--head".equals(args[i]) && i + 1 < args.length) {
                head = args[++i];
            } else if ("--public-key".equals(args[i]) && i + 1 < args.length) {
                publicKey = args[++i];
            } else {
                args = new String[0];   // unknown option: fall through to usage
                break;
            }
        }
        if (args.length < 2) {
            System.err.println("usage: verify-bundle <bundle.json> [--head HASH] [--public-key BASE64]");
            return 2;
        }
        ObjectMapper json = new ObjectMapper();
        try {
            VerifyResult result = HashChain.verifyBundle(json.readValue(Path.of(args[1]).toFile(), Bundle.class),
                    publicKey);
            if (result.valid() && head != null && !result.headHash().equals(head)) {
                result = new VerifyResult(false, 0, result.headSeq(), result.headHash(), null,
                        "HEAD_MISMATCH", "bundle head differs from the trusted checkpoint");
            }
            System.out.println(json.writerWithDefaultPrettyPrinter().writeValueAsString(result));
            return result.valid() ? 0 : 1;
        } catch (IOException e) {
            System.err.println("cannot read bundle: " + e.getMessage());
            return 2;
        }
    }
}
