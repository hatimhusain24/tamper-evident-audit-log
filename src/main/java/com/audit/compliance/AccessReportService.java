package com.audit.compliance;

import com.audit.chain.AuditRecord;
import com.audit.chain.HashChain;
import com.audit.compliance.AccessReport.Access;
import com.audit.store.AuditStore;
import java.time.Clock;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import org.springframework.stereotype.Service;

/** Scenario C: regulator-facing access report (see docs/04_SCENARIO_C_COMPLIANCE.md). */
@Service
public class AccessReportService {

    static final String ACCOUNT_RESOURCE = "CLIENT_ACCOUNT";

    private final AuditStore store;
    private final Clock clock;

    public AccessReportService(AuditStore store, Clock clock) {
        this.store = store;
        this.clock = clock;
    }

    public AccessReport accessReport(String accountId, Instant from, Instant to, String requestedBy) {
        var integrity = store.verify();

        List<Access> accesses = new ArrayList<>();
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
            byAction.merge(a.action(), 1L, Long::sum);
            byActor.merge(a.actorId(), 1L, Long::sum);
        });
        var scope = new AccessReport.Scope(ACCOUNT_RESOURCE, accountId,
                from == null ? null : AuditStore.iso(from), to == null ? null : AuditStore.iso(to));
        var body = new AccessReport.Body(scope, AuditStore.iso(clock.instant()), requestedBy, integrity,
                new AccessReport.Summary(accesses.size(), byActor.size(), byAction, byActor),
                accesses.stream().filter(a -> a.purpose() == null).map(Access::seq).toList(), accesses);

        String digest = HashChain.sha256(HashChain.canonical(body));
        Map<String, Object> scopeMap = new HashMap<>();   // Map.of() rejects null scope values
        scopeMap.put("accountId", accountId);
        scopeMap.put("from", scope.from());
        scopeMap.put("to", scope.to());
        AuditRecord event = store.append(HashChain.REPORT_EVENT, requestedBy, requestedBy, // audit the auditors
                "COMPLIANCE_REPORT", accountId == null ? "*" : accountId,
                Map.of("scope", scopeMap, "accessCount", accesses.size(), "reportDigest", digest));
        return new AccessReport(body.scope(), body.generatedAt(), body.generatedBy(), body.integrity(),
                body.summary(), body.exceptions(), body.accesses(), digest,
                new AccessReport.EventRef(event.seq(), event.hash()));
    }

    private static Access access(AuditRecord e) {
        Map<String, Object> payload = e.payload() == null ? Map.of() : e.payload();   // corrupt row
        return new Access(e.seq(), e.timestamp(), e.actorId(), e.recordedBy(), e.eventType(), e.resourceId(),
                payload.get("purpose"), payload.get("channel"), e.hash());
    }
}
