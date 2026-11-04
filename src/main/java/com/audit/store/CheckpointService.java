package com.audit.store;

import com.audit.chain.HashChain;
import com.audit.chain.SigningKey;
import com.audit.chain.VerifyResult;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.time.Clock;
import java.util.List;
import java.util.Optional;
import java.util.TreeMap;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

/**
 * Signed checkpoints of the chain head, appended to a file that should live on separate,
 * append-only (WORM) storage. Verification uses the latest checkpoint as an anchor, so records
 * deleted from the end of the log are detected automatically, and an edited checkpoint fails its
 * Ed25519 signature.
 */
@Service
public class CheckpointService {

    private static final Logger SECURITY_LOG = LoggerFactory.getLogger("audit.security");

    /** One line of the checkpoint file. signature covers canonical {createdAt, hash, seq}. */
    public record Checkpoint(long seq, String hash, String createdAt, String signature) {
        byte[] signedBytes() {
            TreeMap<String, Object> body = new TreeMap<>();
            body.put("seq", seq);
            body.put("hash", hash);
            body.put("createdAt", createdAt);
            return HashChain.canonical(body);
        }
    }

    private final AuditStore store;
    private final SigningKey signingKey;
    private final Clock clock;
    private final Path file;
    private final ObjectMapper json = new ObjectMapper();

    public CheckpointService(AuditStore store, SigningKey signingKey, Clock clock,
                             @Value("${audit.checkpoint.file:audit-checkpoints.jsonl}") String file) {
        this.store = store;
        this.signingKey = signingKey;
        this.clock = clock;
        this.file = Path.of(file);
    }

    /**
     * Write a checkpoint if the head moved since the last one; returns the latest checkpoint.
     * Empty when the log is empty or fails full verification: a broken chain is never signed and
     * an old checkpoint is not returned as if all were well.
     */
    @Scheduled(initialDelayString = "${audit.checkpoint.interval-ms:3600000}",
               fixedDelayString = "${audit.checkpoint.interval-ms:3600000}")
    public synchronized Optional<Checkpoint> checkpoint() {
        VerifyResult head = store.verify(null, null);
        if (!head.valid()) {
            SECURITY_LOG.error("checkpoint refused: chain fails verification violation={} seq={}",
                    head.violation(), head.firstInvalidSeq());
            return Optional.empty();
        }
        if (head.headSeq() == 0) {
            return Optional.empty();
        }
        Optional<Checkpoint> last = latest();
        if (last.isPresent() && last.get().seq() == head.headSeq()) {
            return last;
        }
        Checkpoint unsigned = new Checkpoint(head.headSeq(), head.headHash(), AuditStore.iso(clock.instant()), null);
        Checkpoint signed = new Checkpoint(unsigned.seq(), unsigned.hash(), unsigned.createdAt(),
                signingKey.sign(unsigned.signedBytes()));
        try {
            Files.writeString(file, json.writeValueAsString(signed) + "\n", StandardCharsets.UTF_8,
                    StandardOpenOption.CREATE, StandardOpenOption.APPEND, StandardOpenOption.SYNC);
        } catch (IOException e) {
            throw new UncheckedIOException("cannot write checkpoint file " + file, e);
        }
        SECURITY_LOG.info("checkpoint written seq={}", signed.seq());
        return Optional.of(signed);
    }

    /** The last checkpoint in the file, or empty if there is none. Signature is not checked here. */
    public Optional<Checkpoint> latest() {
        if (!Files.exists(file)) {
            return Optional.empty();
        }
        try {
            List<String> lines = Files.readAllLines(file, StandardCharsets.UTF_8).stream()
                    .filter(l -> !l.isBlank()).toList();
            return lines.isEmpty() ? Optional.empty()
                    : Optional.of(json.readValue(lines.get(lines.size() - 1), Checkpoint.class));
        } catch (JsonProcessingException e) {
            return Optional.of(new Checkpoint(0, null, null, null));   // unreadable: fails the signature check
        } catch (IOException e) {
            throw new UncheckedIOException("cannot read checkpoint file " + file, e);
        }
    }

    public boolean isAuthentic(Checkpoint c) {
        return c.hash() != null && SigningKey.verify(signingKey.publicKeyBase64(), c.signedBytes(), c.signature());
    }
}
