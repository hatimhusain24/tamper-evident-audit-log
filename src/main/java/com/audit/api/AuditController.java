package com.audit.api;

import com.audit.api.Dtos.EventPage;
import com.audit.api.Dtos.EventView;
import com.audit.api.Dtos.RedactionRequest;
import com.audit.api.Dtos.ReportRequest;
import com.audit.api.Dtos.RetentionRequest;
import com.audit.api.Dtos.RetentionResponse;
import com.audit.chain.Bundle;
import com.audit.chain.HashChain;
import com.audit.chain.VerifyResult;
import com.audit.compliance.AccessReport;
import com.audit.compliance.AccessReportService;
import com.audit.store.AuditStore;
import com.audit.security.LogSafe;
import io.micrometer.core.instrument.MeterRegistry;
import jakarta.validation.Valid;
import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.Pattern;
import java.time.Instant;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.format.annotation.DateTimeFormat;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

/**
 * Append-only audit API. There is deliberately no update or delete endpoint. Who may call what
 * is decided in SecurityConfig; this class only uses the authenticated name for attribution.
 * Every POST requires application/json: a cross-site HTML form cannot send it, which is the CSRF
 * defence for this stateless API.
 */
@RestController
public final class AuditController {

    static final int MAX_PAYLOAD_BYTES = 32 * 1024;
    private static final Logger SECURITY_LOG = LoggerFactory.getLogger("audit.security");

    private final AuditStore store;
    private final AccessReportService reports;
    private final double retentionDays;
    private final Set<String> sensitiveFields;
    private final MeterRegistry metrics;

    public AuditController(AuditStore store, AccessReportService reports, MeterRegistry metrics,
                           @Value("${audit.retention-days:2190}") double retentionDays,
                           @Value("${audit.sensitive-fields:}") Set<String> sensitiveFields) {
        if (retentionDays < store.retentionMinDays()) {   // fail fast on an unsafe deployment
            throw new IllegalStateException("audit.retention-days (" + retentionDays
                    + ") is below audit.retention-min-days (" + store.retentionMinDays() + ")");
        }
        this.store = store;
        this.reports = reports;
        this.retentionDays = retentionDays;
        this.sensitiveFields = Set.copyOf(sensitiveFields);
        this.metrics = metrics;
    }

    /** READERs see sensitive payload fields masked; COMPLIANCE and ADMIN see them in full. */
    private Set<String> maskFor(Authentication auth) {
        boolean privileged = auth.getAuthorities().stream().anyMatch(a ->
                a.getAuthority().equals("ROLE_COMPLIANCE") || a.getAuthority().equals("ROLE_ADMIN"));
        return privileged ? Set.of() : sensitiveFields;
    }

    /**
     * Append an event. With an Idempotency-Key header a retried request returns the original
     * record (200, Idempotent-Replayed: true) instead of writing a duplicate.
     */
    @PostMapping(value = "/audit/events", consumes = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<EventView> write(@Valid @RequestBody EventRequest event, Authentication auth,
            @RequestHeader(value = "Idempotency-Key", required = false)
            @Pattern(regexp = "^[A-Za-z0-9_-]{8,64}$") String idempotencyKey) {
        if (HashChain.SYSTEM_EVENTS.contains(event.eventType())) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST,
                    event.eventType() + " is a reserved system event type");
        }
        Map<String, Object> payload = event.payload() == null ? Map.of() : event.payload();
        if (HashChain.canonical(payload).length > MAX_PAYLOAD_BYTES) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "payload exceeds " + MAX_PAYLOAD_BYTES + " bytes");
        }
        if (idempotencyKey != null) {   // keys are scoped per caller
            AuditStore.Appended result = store.appendOnce(auth.getName() + ":" + idempotencyKey, event.eventType(),
                    event.actorId(), auth.getName(), event.resourceType(), event.resourceId(), payload);
            if (result.replayed()) {
                return ResponseEntity.ok().header("Idempotent-Replayed", "true").body(EventView.of(result.record()));
            }
            metrics.counter("audit.events.written").increment();
            return ResponseEntity.status(HttpStatus.CREATED).body(EventView.of(result.record()));
        }
        EventView written = EventView.of(store.append(event.eventType(), event.actorId(), auth.getName(),
                event.resourceType(), event.resourceId(), payload));
        metrics.counter("audit.events.written").increment();
        return ResponseEntity.status(HttpStatus.CREATED).body(written);
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
            @RequestParam(defaultValue = "0") @Min(0) long cursor,
            Authentication auth) {
        Map<String, String> filters = new HashMap<>();
        filters.put("actorId", actorId);
        filters.put("resourceType", resourceType);
        filters.put("resourceId", resourceId);
        filters.put("eventType", eventType);
        AuditStore.Page page = store.query(filters, from, to, limit, cursor);
        Set<String> mask = maskFor(auth);
        return new EventPage(page.items().stream().map(r -> EventView.of(r, mask)).toList(), page.nextCursor());
    }

    /**
     * Walks the full chain: hashes, MACs and policies. Returns valid, first bad seq and violation
     * type, plus the head. Store the head externally (WORM) and pass it back as an anchor later to
     * prove no records were removed from the end.
     */
    @GetMapping("/audit/verify")
    public VerifyResult verify(@RequestParam(required = false) @Min(1) Long anchorSeq,
                               @RequestParam(required = false) @Pattern(regexp = "^[0-9a-f]{64}$") String anchorHash) {
        if ((anchorSeq == null) != (anchorHash == null)) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "give both anchorSeq and anchorHash, or neither");
        }
        VerifyResult result = store.verify(anchorSeq, anchorHash);
        if (!result.valid()) {   // tamper evidence: alert-worthy
            metrics.counter("audit.verify.failures", "violation", result.violation()).increment();
            SECURITY_LOG.error("chain verification failed violation={} seq={} detail={}",
                    result.violation(), result.firstInvalidSeq(), result.detail());
        }
        return result;
    }

    @PostMapping(value = "/audit/events/{seq}/redactions", consumes = MediaType.APPLICATION_JSON_VALUE)
    @ResponseStatus(HttpStatus.CREATED)
    public EventView redact(@PathVariable long seq, @Valid @RequestBody RedactionRequest body, Authentication auth) {
        EventView event = EventView.of(store.redact(seq, body.fields(), body.reason(), auth.getName()));
        SECURITY_LOG.info("redaction seq={} fields={} by={}", seq, LogSafe.clean(String.valueOf(body.fields())),
                LogSafe.clean(auth.getName()));
        return event;
    }

    @PostMapping(value = "/audit/retention/run", consumes = MediaType.APPLICATION_JSON_VALUE)
    public RetentionResponse runRetention(@Valid @RequestBody(required = false) RetentionRequest body,
                                          Authentication auth) {
        double days = body == null || body.olderThanDays() == null ? retentionDays : body.olderThanDays();
        AuditStore.RetentionResult result = store.archive(days, auth.getName());
        SECURITY_LOG.info("retention run olderThanDays={} archived={} by={}", days, result.archivedCount(),
                LogSafe.clean(auth.getName()));
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

    /**
     * Scenario C: who accessed client account data, when and why, with integrity proof. A POST,
     * because generating a report is itself recorded in the chain.
     */
    @PostMapping(value = "/audit/reports/account-access", consumes = MediaType.APPLICATION_JSON_VALUE)
    public AccessReport accountAccessReport(@Valid @RequestBody(required = false) ReportRequest body,
                                            Authentication auth) {
        ReportRequest scope = body == null ? new ReportRequest(null, null, null) : body;
        return reports.accessReport(scope.accountId(), scope.from(), scope.to(), auth.getName());
    }
}
