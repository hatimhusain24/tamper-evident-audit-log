package com.audit;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.concurrent.atomic.AtomicReference;

/**
 * A clock tests can move forward (years of retention) or backward (clock corrections). Like a
 * real clock it ticks: each read is 1 microsecond later than the previous one.
 */
public final class TestClock extends Clock {

    private final AtomicReference<Instant> now = new AtomicReference<>(Instant.now());

    public void set(Instant instant) {
        now.set(instant);
    }

    public void advanceDays(long days) {
        now.updateAndGet(t -> t.plus(Duration.ofDays(days)));
    }

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
        return now.getAndUpdate(t -> t.plusNanos(1_000));
    }
}
