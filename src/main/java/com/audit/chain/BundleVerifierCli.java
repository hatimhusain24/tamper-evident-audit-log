package com.audit.chain;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.nio.file.Path;

/**
 * Offline verifier for export bundles: no server or database needed.
 *
 * <pre>java -jar target/audit-log.jar verify-bundle bundle.json [trusted-head-hash]</pre>
 * Exit code 0 = verified, 1 = verification failed, 2 = usage or read error.
 */
public final class BundleVerifierCli {

    private BundleVerifierCli() {
    }

    public static int run(String[] args) {
        if (args.length < 2) {
            System.err.println("usage: verify-bundle <bundle.json> [trusted-head-hash]");
            return 2;
        }
        ObjectMapper json = new ObjectMapper();
        try {
            VerifyResult result = HashChain.verifyBundle(json.readValue(Path.of(args[1]).toFile(), Bundle.class));
            if (result.valid() && args.length > 2 && !result.headHash().equals(args[2])) {
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
