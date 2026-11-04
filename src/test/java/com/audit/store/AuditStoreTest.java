package com.audit.store;

import static org.assertj.core.api.Assertions.assertThat;

import com.audit.chain.AuditRecord;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.sqlite.SQLiteDataSource;

/** Store-level edge cases that need control over the clock. */
class AuditStoreTest {

    /** A clock the test can move, including backwards. */
    static final class MovableClock extends Clock {
        Instant now = Instant.parse("2026-01-01T12:00:00Z");

        @Override
        public ZoneId getZone() {
            return ZoneOffset.UTC;
        }

        @Override
        public Clock withZone(ZoneId zone) {
            return this;
        }

        @Override
        public Instant instant() {
            return now;
        }
    }

    @Test
    void timestampsStayMonotonicWhenTheClockStepsBack(@TempDir Path dir) {
        SQLiteDataSource ds = new SQLiteDataSource();
        ds.setUrl("jdbc:sqlite:" + dir.resolve("a.db"));
        MovableClock clock = new MovableClock();
        AuditStore store = new AuditStore(ds, clock);

        AuditRecord first = store.append("X_Y", "a", "r", "1", Map.of());
        clock.now = clock.now.minusSeconds(3600);                    // NTP correction, VM resume, etc.
        AuditRecord second = store.append("X_Y", "a", "r", "1", Map.of());

        assertThat(second.timestamp()).isEqualTo(first.timestamp());
        assertThat(store.verify().valid()).isTrue();
    }

    @Test
    void retentionUsesTheConfiguredWindow(@TempDir Path dir) {
        SQLiteDataSource ds = new SQLiteDataSource();
        ds.setUrl("jdbc:sqlite:" + dir.resolve("b.db"));
        MovableClock clock = new MovableClock();
        AuditStore store = new AuditStore(ds, clock);
        store.append("X_Y", "a", "r", "1", Map.of());                // day 0
        clock.now = clock.now.plusSeconds(10 * 86_400);
        store.append("X_Y", "a", "r", "1", Map.of());                // day 10

        AuditStore.RetentionResult result = store.archive(5, "ops"); // older than 5 days
        assertThat(result.archivedCount()).isEqualTo(1);
        assertThat(result.throughSeq()).isEqualTo(1);
        assertThat(store.verify().valid()).isTrue();
    }
}
