package com.audit.perf;

import static org.assertj.core.api.Assertions.assertThat;

import com.audit.store.AuditStore;
import com.zaxxer.hikari.HikariDataSource;
import java.nio.file.Path;
import java.time.Clock;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * Reproducible numbers for docs/06_TESTING.md. Opt-in (tagged "perf"):
 * mvn test -Dtest=PerfBenchmarkTest -Dperf.excluded=none
 */
@Tag("perf")
class PerfBenchmarkTest {

    @Test
    void appendVerifyAndDeepPage(@TempDir Path dir) {
        try (HikariDataSource ds = new HikariDataSource()) {
            ds.setMaximumPoolSize(4);   // same pool size as the service
            ds.setJdbcUrl("jdbc:sqlite:" + dir.resolve("perf.db") + "?journal_mode=WAL&busy_timeout=5000&secure_delete=true");
            AuditStore store = new AuditStore(ds, Clock.systemUTC(), 2190, com.audit.chain.IntegrityKey.of("perf-benchmark-hmac-key-0123456789ab"));
            Map<String, Object> payload = Map.of("a", 1, "b", "x".repeat(100), "c", List.of(1, 2, 3));
            for (int i = 0; i < 500; i++) {
                store.append("RECORD_UPDATED", "u", "svc", "ACCOUNT", "a", payload);   // JIT warm-up
            }
            long t0 = System.nanoTime();
            for (int i = 0; i < 10_000; i++) {
                store.append("RECORD_UPDATED", "u", "svc", "ACCOUNT", "a", payload);
            }
            long t1 = System.nanoTime();
            var result = store.verify();
            long t2 = System.nanoTime();
            store.query(Map.of("actorId", "u"), null, null, 50, 9_000);
            long t3 = System.nanoTime();

            System.out.printf("PERF append: %.0f events/s | verify %d records: %.2f s | page at depth 9000: %.1f ms%n",
                    10_000 / ((t1 - t0) / 1e9), result.recordsChecked(), (t2 - t1) / 1e9, (t3 - t2) / 1e6);
            assertThat(result.valid()).isTrue();
            assertThat((t2 - t1) / 1e9).isLessThan(10);   // generous bound: catches order-of-magnitude regressions
        }
    }
}
