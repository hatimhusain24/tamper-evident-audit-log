package com.audit.security;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;
import org.springframework.jdbc.core.JdbcTemplate;

/**
 * Counts requests per client per minute. {@link #inMemory()} serves one instance;
 * {@link #database(JdbcTemplate)} keeps the counters in the shared database, so every instance
 * behind a load balancer enforces one limit together.
 */
public interface RateLimiter {

    /** Count one request and return the client's total in this minute window. */
    int increment(String client, long minute);

    static RateLimiter inMemory() {
        record Window(long minute, AtomicInteger count) {
        }
        Map<String, Window> windows = new ConcurrentHashMap<>();
        return (client, minute) -> {
            if (windows.size() > 10_000) {
                windows.clear();   // bounded memory; worst case a client gets a fresh window
            }
            return windows.compute(client, (k, old) ->
                    old == null || old.minute() != minute ? new Window(minute, new AtomicInteger()) : old)
                    .count().incrementAndGet();
        };
    }

    /** One atomic upsert per request; old windows are pruned as the minute rolls over. */
    static RateLimiter database(JdbcTemplate jdbc) {
        jdbc.execute("CREATE TABLE IF NOT EXISTS rate_limits (client TEXT NOT NULL, minute INTEGER NOT NULL, "
                + "count INTEGER NOT NULL, PRIMARY KEY (client, minute))");
        long[] lastPruned = {0};
        return (client, minute) -> {
            if (lastPruned[0] != minute) {
                lastPruned[0] = minute;
                jdbc.update("DELETE FROM rate_limits WHERE minute < ?", minute - 1);
            }
            Integer count = jdbc.queryForObject("INSERT INTO rate_limits (client, minute, count) VALUES (?, ?, 1) "
                    + "ON CONFLICT (client, minute) DO UPDATE SET count = count + 1 RETURNING count",
                    Integer.class, client, minute);
            return count == null ? 1 : count;
        };
    }
}
