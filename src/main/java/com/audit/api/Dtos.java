package com.audit.api;

import com.audit.chain.AuditRecord;
import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.PositiveOrZero;
import jakarta.validation.constraints.Size;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/** Request and response shapes of the public API (the OpenAPI schema is generated from these). */
public final class Dtos {

    static final String MASK = "***";

    private Dtos() {
    }

    /** Read model of a record: salts stay internal; sensitive fields can be masked. */
    public record EventView(long seq, String timestamp, String eventType, String actorId, String recordedBy,
                            String resourceType, String resourceId, Map<String, Object> payload,
                            Map<String, String> fieldHashes, String prevHash, String hash) {

        static EventView of(AuditRecord r) {
            return of(r, Set.of());
        }

        /** Masking only changes this view; the stored record and its hashes are untouched. */
        static EventView of(AuditRecord r, Set<String> maskedFields) {
            if (r == null) {
                return null;
            }
            Map<String, Object> payload = r.payload();
            if (payload != null && !maskedFields.isEmpty()) {
                payload = new LinkedHashMap<>(payload);
                payload.replaceAll((k, v) -> maskedFields.contains(k) ? MASK : v);
            }
            return new EventView(r.seq(), r.timestamp(), r.eventType(), r.actorId(), r.recordedBy(),
                    r.resourceType(), r.resourceId(), payload, r.fieldHashes(), r.prevHash(), r.hash());
        }
    }

    /** nextCursor: pass back as ?cursor= for the next page; null means last page. */
    public record EventPage(List<EventView> items, Long nextCursor) {
    }

    /** The requester is the authenticated user, never a body field. */
    public record RedactionRequest(
            @NotEmpty @Size(max = 50) List<@NotBlank @Size(max = 128) String> fields,
            @NotBlank @Size(min = 3, max = 500) String reason) {
    }

    /** olderThanDays defaults to audit.retention-days and can never go below audit.retention-min-days. */
    public record RetentionRequest(@PositiveOrZero @Max(36_500) Double olderThanDays) {
    }

    /** event = the chained RECORDS_ARCHIVED event that authorizes this run (null if nothing archived). */
    public record RetentionResponse(long archivedCount, Long throughSeq, EventView event) {
    }

    /** Scenario C report scope; every field optional (no accountId = all client accounts). */
    public record ReportRequest(@Size(max = 128) String accountId, Instant from, Instant to) {
    }
}
