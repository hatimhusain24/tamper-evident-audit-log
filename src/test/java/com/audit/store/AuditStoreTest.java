package com.audit.store;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.audit.TestClock;
import com.audit.chain.AuditRecord;
import java.nio.file.Path;
import java.time.Instant;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.sqlite.SQLiteDataSource;

/** Store-level edge cases that need control over the clock and the retention floor. */
class AuditStoreTest {

    static final double SIX_YEARS = 2190;
    static final String KEY = "store-test-hmac-key-0123456789abcdef";

    static SQLiteDataSource dataSource(Path file) {
        SQLiteDataSource ds = new SQLiteDataSource();
        ds.setUrl("jdbc:sqlite:" + file);
        return ds;
    }

    static TestClock clockAt(String instant) {
        TestClock clock = new TestClock();
        clock.set(Instant.parse(instant));
        return clock;
    }

    @Test
    void timestampsStayMonotonicWhenTheClockStepsBack(@TempDir Path dir) {
        TestClock clock = clockAt("2026-01-01T12:00:00Z");
        AuditStore store = new AuditStore(dataSource(dir.resolve("a.db")), clock, SIX_YEARS, com.audit.chain.IntegrityKey.of(KEY));

        AuditRecord first = store.append("X_Y", "a", "svc", "r", "1", Map.of());
        clock.advanceDays(-1);                                    // NTP correction, VM resume, etc.
        AuditRecord second = store.append("X_Y", "a", "svc", "r", "1", Map.of());

        assertThat(second.timestamp()).isEqualTo(first.timestamp());
        assertThat(store.verify().valid()).isTrue();
    }

    @Test
    void retentionArchivesOnlyRecordsOlderThanTheWindow(@TempDir Path dir) {
        TestClock clock = clockAt("2020-01-01T00:00:00Z");
        AuditStore store = new AuditStore(dataSource(dir.resolve("b.db")), clock, SIX_YEARS, com.audit.chain.IntegrityKey.of(KEY));
        store.append("X_Y", "a", "svc", "r", "1", Map.of());                 // year 0
        clock.advanceDays(4 * 365);
        store.append("X_Y", "a", "svc", "r", "1", Map.of());                 // year 4
        clock.advanceDays(3 * 365);                                   // now year 7

        AuditStore.RetentionResult result = store.archive(SIX_YEARS, "ops");
        assertThat(result.archivedCount()).isEqualTo(1);
        assertThat(result.throughSeq()).isEqualTo(1);
        assertThat(store.verify().valid()).isTrue();
    }

    @Test
    void storeRefusesAWindowBelowTheFloor(@TempDir Path dir) {
        AuditStore store = new AuditStore(dataSource(dir.resolve("c.db")), clockAt("2026-01-01T00:00:00Z"), SIX_YEARS, com.audit.chain.IntegrityKey.of(KEY));
        assertThatThrownBy(() -> store.archive(30, "ops")).isInstanceOf(AuditStore.PolicyViolation.class);
    }

    @Test
    void verifyFlagsAnArchiveRunBelowTheFloor(@TempDir Path dir) {
        Path file = dir.resolve("d.db");
        TestClock clock = clockAt("2026-01-01T00:00:00Z");
        AuditStore weakDeployment = new AuditStore(dataSource(file), clock, 0, com.audit.chain.IntegrityKey.of(KEY));   // misconfigured once
        weakDeployment.append("X_Y", "a", "svc", "r", "1", Map.of());
        clock.advanceDays(1);
        weakDeployment.archive(0, "ops");

        AuditStore compliant = new AuditStore(dataSource(file), clock, SIX_YEARS, com.audit.chain.IntegrityKey.of(KEY));
        var result = compliant.verify();
        assertThat(result.valid()).isFalse();
        assertThat(result.violation()).isEqualTo("RETENTION_POLICY_VIOLATION");
        assertThat(result.firstInvalidSeq()).isEqualTo(2);
    }

    @Test
    void keyRotationKeepsOldRecordsVerifiable(@TempDir Path dir) {
        Path file = dir.resolve("e.db");
        TestClock clock = clockAt("2026-01-01T00:00:00Z");
        String k1 = "first-hmac-key-0123456789abcdef0123";
        String k2 = "second-hmac-key-0123456789abcdef012";
        AuditStore before = new AuditStore(dataSource(file), clock, SIX_YEARS, com.audit.chain.IntegrityKey.of("k1", k1, ""));
        before.append("X_Y", "a", "svc", "r", "1", Map.of());

        var rotated = com.audit.chain.IntegrityKey.of("k2", k2, "k1=" + k1);
        AuditStore after = new AuditStore(dataSource(file), clock, SIX_YEARS, rotated);
        AuditRecord fresh = after.append("X_Y", "a", "svc", "r", "1", Map.of());
        assertThat(fresh.mac()).startsWith("k2:");
        assertThat(after.verify().valid()).isTrue();                          // k1 and k2 records both check

        AuditStore k1Dropped = new AuditStore(dataSource(file), clock, SIX_YEARS, com.audit.chain.IntegrityKey.of("k2", k2, ""));
        var result = k1Dropped.verify();
        assertThat(result.violation()).isEqualTo("MAC_MISMATCH");             // old key removed too early
        assertThat(result.firstInvalidSeq()).isEqualTo(1);
    }
}
