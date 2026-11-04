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
        AuditStore store = new AuditStore(dataSource(dir.resolve("a.db")), clock, SIX_YEARS);

        AuditRecord first = store.append("X_Y", "a", "r", "1", Map.of());
        clock.advanceDays(-1);                                    // NTP correction, VM resume, etc.
        AuditRecord second = store.append("X_Y", "a", "r", "1", Map.of());

        assertThat(second.timestamp()).isEqualTo(first.timestamp());
        assertThat(store.verify().valid()).isTrue();
    }

    @Test
    void retentionArchivesOnlyRecordsOlderThanTheWindow(@TempDir Path dir) {
        TestClock clock = clockAt("2020-01-01T00:00:00Z");
        AuditStore store = new AuditStore(dataSource(dir.resolve("b.db")), clock, SIX_YEARS);
        store.append("X_Y", "a", "r", "1", Map.of());                 // year 0
        clock.advanceDays(4 * 365);
        store.append("X_Y", "a", "r", "1", Map.of());                 // year 4
        clock.advanceDays(3 * 365);                                   // now year 7

        AuditStore.RetentionResult result = store.archive(SIX_YEARS, "ops");
        assertThat(result.archivedCount()).isEqualTo(1);
        assertThat(result.throughSeq()).isEqualTo(1);
        assertThat(store.verify().valid()).isTrue();
    }

    @Test
    void storeRefusesAWindowBelowTheFloor(@TempDir Path dir) {
        AuditStore store = new AuditStore(dataSource(dir.resolve("c.db")), clockAt("2026-01-01T00:00:00Z"), SIX_YEARS);
        assertThatThrownBy(() -> store.archive(30, "ops")).isInstanceOf(AuditStore.PolicyViolation.class);
    }

    @Test
    void verifyFlagsAnArchiveRunBelowTheFloor(@TempDir Path dir) {
        Path file = dir.resolve("d.db");
        TestClock clock = clockAt("2026-01-01T00:00:00Z");
        AuditStore weakDeployment = new AuditStore(dataSource(file), clock, 0);   // misconfigured once
        weakDeployment.append("X_Y", "a", "r", "1", Map.of());
        clock.advanceDays(1);
        weakDeployment.archive(0, "ops");

        AuditStore compliant = new AuditStore(dataSource(file), clock, SIX_YEARS);
        var result = compliant.verify();
        assertThat(result.valid()).isFalse();
        assertThat(result.violation()).isEqualTo("RETENTION_POLICY_VIOLATION");
        assertThat(result.firstInvalidSeq()).isEqualTo(2);
    }
}
