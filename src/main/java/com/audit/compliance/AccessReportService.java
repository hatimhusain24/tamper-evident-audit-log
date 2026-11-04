package com.audit.compliance;

import com.audit.chain.AuditRecord;
import com.audit.chain.HashChain;
import com.audit.store.AuditStore;
import java.time.Clock;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import org.springframework.stereotype.Service;

/** Scenario C: regulator-facing access report (see docs/04_SCENARIO_C_COMPLIANCE.md). */
@Service
public class AccessReportService {

    static final String ACCOUNT_RESOURCE = "CLIENT_ACCOUNT";
    static final String REPORT_EVENT = "COMPLIANCE_REPORT_GENERATED";

    private final AuditStore store;
    private final Clock clock;

    public AccessReportService(AuditStore store, Clock clock) {
        this.store = store;
        this.clock = clock;
    }

    public Map<String, Object> accessReport(String accountId, Instant from, Instant to, String requestedBy) {
        var integrity = store.verify();

        List<Map<String, Object>> accesses = new ArrayList<>();
        Map<String, String> filters = new HashMap<>();
        filters.put("resourceType", ACCOUNT_RESOURCE);
        filters.put("resourceId", accountId);
        Long cursor = 0L;
        while (cursor != null) {   // reuse the indexed keyset query, page by page
            AuditStore.Page page = store.query(filters, from, to, 500, cursor);
            page.items().forEach(e -> accesses.add(access(e)));
            cursor = page.nextCursor();
        }

        Map<String, Long> byAction = new TreeMap<>();
        Map<String, Long> byActor = new TreeMap<>();
        accesses.forEach(a -> {
            byAction.merge((String) a.get("action"), 1L, Long::sum);
            byActor.merge((String) a.get("actorId"), 1L, Long::sum);
        });
        Map<String, Object> scope = new LinkedHashMap<>();
        scope.put("resourceType", ACCOUNT_RESOURCE);
        scope.put("accountId", accountId);
        scope.put("from", from == null ? null : AuditStore.iso(from));
        scope.put("to", to == null ? null : AuditStore.iso(to));

        Map<String, Object> report = new LinkedHashMap<>();
        report.put("scope", scope);
        report.put("generatedAt", AuditStore.iso(clock.instant()));
        report.put("generatedBy", requestedBy);
        report.put("integrity", integrity);
        report.put("summary", Map.of("totalAccesses", accesses.size(),
                "distinctActors", byActor.size(),
                "byAction", byAction, "byActor", byActor));
        report.put("exceptions", accesses.stream().filter(a -> a.get("purpose") == null)
                .map(a -> a.get("seq")).toList());
        report.put("accesses", accesses);

        String digest = HashChain.sha256(HashChain.canonical(report));
        AuditRecord event = store.append(REPORT_EVENT, requestedBy, "COMPLIANCE_REPORT",   // audit the auditors
                accountId == null ? "*" : accountId,
                Map.of("scope", scope, "accessCount", accesses.size(), "reportDigest", digest));
        report.put("reportDigest", digest);
        report.put("reportEvent", Map.of("seq", event.seq(), "hash", event.hash()));
        return report;
    }

    /** Data minimization: access metadata only, never payload contents. */
    private static Map<String, Object> access(AuditRecord e) {
        Map<String, Object> a = new LinkedHashMap<>();
        a.put("seq", e.seq());
        a.put("timestamp", e.timestamp());
        a.put("actorId", e.actorId());
        a.put("action", e.eventType());
        a.put("accountId", e.resourceId());
        Map<String, Object> payload = e.payload() == null ? Map.of() : e.payload();   // corrupt row
        a.put("purpose", payload.get("purpose"));
        a.put("channel", payload.get("channel"));
        a.put("hash", e.hash());
        return a;
    }
}
