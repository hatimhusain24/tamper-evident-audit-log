package com.audit.api;

import com.audit.chain.AuditRecord;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.PositiveOrZero;
import jakarta.validation.constraints.Size;
import java.util.List;
import java.util.Map;

/** Request and response shapes of the public API (the OpenAPI schema is generated from these). */
public final class Dtos {

    private Dtos() {
    }

    /** Read model of a record: salts stay internal. */
    public record EventView(long seq, String timestamp, String eventType, String actorId,
                            String resourceType, String resourceId, Map<String, Object> payload,
                            Map<String, String> fieldHashes, String prevHash, String hash) {

        static EventView of(AuditRecord r) {
            return r == null ? null : new EventView(r.seq(), r.timestamp(), r.eventType(), r.actorId(),
                    r.resourceType(), r.resourceId(), r.payload(), r.fieldHashes(), r.prevHash(), r.hash());
        }
    }

    /** nextCursor: pass back as ?cursor= for the next page; null means last page. */
    public record EventPage(List<EventView> items, Long nextCursor) {
    }

    public record RedactionRequest(
            @NotEmpty @Size(max = 50) List<@NotBlank @Size(max = 128) String> fields,
            @NotBlank @Size(min = 3, max = 500) String reason,
            @NotBlank @Size(max = 128) String requestedBy) {
    }

    /** olderThanDays defaults to audit.retention-days. */
    public record RetentionRequest(@PositiveOrZero Double olderThanDays, @Size(max = 128) String requestedBy) {
    }

    /** event = the chained RECORDS_ARCHIVED event that authorizes this run (null if nothing archived). */
    public record RetentionResponse(long archivedCount, Long throughSeq, EventView event) {
    }
}
