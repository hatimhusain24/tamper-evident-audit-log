package com.audit.store;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.audit.chain.IntegrityKey;
import com.audit.security.RateLimiter;
import com.zaxxer.hikari.HikariDataSource;
import java.nio.file.Path;
import java.time.Clock;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.jdbc.core.JdbcTemplate;

/**
 * Two service instances (separate stores, separate connection pools, separate in-process locks)
 * sharing one database: the database lock alone must keep the chain from forking, and the
 * database rate limiter must enforce one shared limit.
 */
class MultiInstanceTest {

    static HikariDataSource pool(Path db) {
        HikariDataSource ds = new HikariDataSource();
        ds.setMaximumPoolSize(4);
        ds.setJdbcUrl("jdbc:sqlite:" + db + "?journal_mode=WAL&busy_timeout=10000&secure_delete=true");
        return ds;
    }

    static AuditStore instance(HikariDataSource ds) {
        return new AuditStore(ds, Clock.systemUTC(), 2190, IntegrityKey.of("multi-instance-hmac-key-0123456789ab"),
                FieldCipher.of("AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=", Set.of("ssn")));
    }

    @Test
    void twoInstancesWritingConcurrentlyNeverForkTheChain(@TempDir Path dir) throws Exception {
        Path db = dir.resolve("shared.db");
        try (HikariDataSource poolA = pool(db); HikariDataSource poolB = pool(db)) {
            AuditStore a = instance(poolA);
            AuditStore b = instance(poolB);
            ExecutorService threads = Executors.newFixedThreadPool(8);
            List<Future<?>> writes = new ArrayList<>();
            for (int i = 0; i < 100; i++) {
                AuditStore target = i % 2 == 0 ? a : b;                  // alternate instances
                int n = i;
                writes.add(threads.submit(() -> target.append("X_Y", "actor-" + n, "svc", "r", "1", Map.of("n", n))));
            }
            for (Future<?> w : writes) {
                w.get();
            }
            threads.shutdown();
            var fromA = a.verify();
            assertThat(fromA.valid()).isTrue();
            assertThat(fromA.recordsChecked()).isEqualTo(100);
            assertThat(b.verify().headHash()).isEqualTo(fromA.headHash());   // both see the same chain
        }
    }

    @Test
    void databaseRateLimiterIsSharedAcrossInstances(@TempDir Path dir) {
        Path db = dir.resolve("limits.db");
        try (HikariDataSource poolA = pool(db); HikariDataSource poolB = pool(db)) {
            RateLimiter a = RateLimiter.database(new JdbcTemplate(poolA));
            RateLimiter b = RateLimiter.database(new JdbcTemplate(poolB));
            assertThat(a.increment("203.0.113.5", 100)).isEqualTo(1);
            assertThat(b.increment("203.0.113.5", 100)).isEqualTo(2);         // same client, other instance
            assertThat(a.increment("203.0.113.5", 100)).isEqualTo(3);
            assertThat(b.increment("198.51.100.7", 100)).isEqualTo(1);        // other client
            assertThat(a.increment("203.0.113.5", 101)).isEqualTo(1);         // next minute: fresh window
            assertThat(new JdbcTemplate(poolA).queryForObject(
                    "SELECT COUNT(*) FROM rate_limits WHERE minute < 100", Integer.class)).isZero();   // pruned
        }
    }

    @Test
    void inMemoryLimiterCountsPerWindow() {
        RateLimiter limiter = RateLimiter.inMemory();
        assertThat(limiter.increment("c", 1)).isEqualTo(1);
        assertThat(limiter.increment("c", 1)).isEqualTo(2);
        assertThat(limiter.increment("c", 2)).isEqualTo(1);
    }

    @Test
    void unknownLimiterStoreRefusesToStart() {
        assertThatThrownBy(() -> new com.audit.security.SecurityConfig().limiterCheck("redis"))
                .hasMessageContaining("memory or database");
    }
}
