package com.audit.api;

import com.audit.api.Dtos.EventPage;
import com.audit.api.Dtos.EventView;
import com.audit.api.Dtos.RedactionRequest;
import com.audit.api.Dtos.RetentionRequest;
import com.audit.api.Dtos.RetentionResponse;
import com.audit.chain.Bundle;
import com.audit.chain.HashChain;
import com.audit.chain.VerifyResult;
import com.audit.compliance.AccessReportService;
import com.audit.store.AuditStore;
import jakarta.validation.Valid;
import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.HashMap;
import java.util.Map;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.format.annotation.DateTimeFormat;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

/** Append-only audit API. There is deliberately no update or delete endpoint. */
@RestController
public class AuditController {

    static final int MAX_PAYLOAD_BYTES = 32 * 1024;

    private final AuditStore store;
    private final AccessReportService reports;
    private final byte[] adminKey;
    private final double retentionDays;

    public AuditController(AuditStore store, AccessReportService reports,
                           @Value("${audit.admin-key:}") String adminKey,
                           @Value("${audit.retention-days:365}") double retentionDays) {
        this.store = store;
        this.reports = reports;
        this.adminKey = adminKey.getBytes(StandardCharsets.UTF_8);
        this.retentionDays = retentionDays;
    }

    /** High-impact operations (redaction, archival, reports) need the admin key when one is set. */
    private void requireAdmin(String key) {
        if (adminKey.length > 0 && (key == null
                || !MessageDigest.isEqual(adminKey, key.getBytes(StandardCharsets.UTF_8)))) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "valid X-Admin-Key header required");
        }
    }

    @GetMapping("/health")
    public Map<String, String> health() {
        return Map.of("status", "ok");
    }

    @PostMapping("/audit/events")
    @ResponseStatus(HttpStatus.CREATED)
    public EventView write(@Valid @RequestBody EventRequest event) {
        if (HashChain.REDACTION_EVENT.equals(event.eventType()) || HashChain.ARCHIVE_EVENT.equals(event.eventType())) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST,
                    event.eventType() + " is a reserved system event type");
        }
        Map<String, Object> payload = event.payload() == null ? Map.of() : event.payload();
        if (HashChain.canonical(payload).length > MAX_PAYLOAD_BYTES) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "payload exceeds " + MAX_PAYLOAD_BYTES + " bytes");
        }
        return EventView.of(store.append(event.eventType(), event.actorId(), event.resourceType(),
                event.resourceId(), payload));
    }

    @GetMapping("/audit/events")
    public EventPage query(
            @RequestParam(required = false) String actorId,
            @RequestParam(required = false) String resourceType,
            @RequestParam(required = false) String resourceId,
            @RequestParam(required = false) String eventType,
            @RequestParam(required = false) @DateTimeFormat(iso = DateTimeFormat.ISO.DATE_TIME) Instant from,
            @RequestParam(required = false) @DateTimeFormat(iso = DateTimeFormat.ISO.DATE_TIME) Instant to,
            @RequestParam(defaultValue = "50") @Min(1) @Max(500) int limit,
            @RequestParam(defaultValue = "0") @Min(0) long cursor) {
        Map<String, String> filters = new HashMap<>();
        filters.put("actorId", actorId);
        filters.put("resourceType", resourceType);
        filters.put("resourceId", resourceId);
        filters.put("eventType", eventType);
        AuditStore.Page page = store.query(filters, from, to, limit, cursor);
        return new EventPage(page.items().stream().map(EventView::of).toList(), page.nextCursor());
    }

    /** Walks the full chain: valid, first bad seq and violation type, plus head to anchor. */
    @GetMapping("/audit/verify")
    public VerifyResult verify() {
        return store.verify();
    }

    @PostMapping("/audit/events/{seq}/redactions")
    @ResponseStatus(HttpStatus.CREATED)
    public EventView redact(@PathVariable long seq,
                            @RequestHeader(value = "X-Admin-Key", required = false) String key,
                            @Valid @RequestBody RedactionRequest body) {
        requireAdmin(key);
        return EventView.of(store.redact(seq, body.fields(), body.reason(), body.requestedBy()));
    }

    @PostMapping("/audit/retention/run")
    public RetentionResponse runRetention(@RequestHeader(value = "X-Admin-Key", required = false) String key,
                                          @Valid @RequestBody(required = false) RetentionRequest body) {
        requireAdmin(key);
        double days = body == null || body.olderThanDays() == null ? retentionDays : body.olderThanDays();
        String by = body == null || body.requestedBy() == null ? "system:retention" : body.requestedBy();
        AuditStore.RetentionResult result = store.archive(days, by);
        return new RetentionResponse(result.archivedCount(), result.throughSeq(), EventView.of(result.event()));
    }

    /** All records for ONE actorId or resourceId, as a bundle anyone can verify offline. */
    @GetMapping("/audit/export")
    public Bundle export(@RequestParam(required = false) String actorId,
                         @RequestParam(required = false) String resourceId) {
        if ((actorId == null) == (resourceId == null)) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "provide exactly one of actorId or resourceId");
        }
        return actorId != null ? store.export(true, actorId) : store.export(false, resourceId);
    }

    /** Scenario C: who accessed client account data, when and why, with integrity proof. */
    @GetMapping("/audit/reports/account-access")
    public Map<String, Object> accountAccessReport(
            @RequestHeader(value = "X-Admin-Key", required = false) String key,
            @RequestParam @NotBlank @Size(max = 128) String requestedBy,
            @RequestParam(required = false) String accountId,
            @RequestParam(required = false) @DateTimeFormat(iso = DateTimeFormat.ISO.DATE_TIME) Instant from,
            @RequestParam(required = false) @DateTimeFormat(iso = DateTimeFormat.ISO.DATE_TIME) Instant to) {
        requireAdmin(key);
        return reports.accessReport(accountId, from, to, requestedBy);
    }
}
