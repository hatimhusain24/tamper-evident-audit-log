package com.audit;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.Map;
import java.util.stream.Stream;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.api.Test;

/** A damaged row must give a typed violation at its seq, never an HTTP 500, and must not break reads. */
class CorruptRecordTest extends ApiTestBase {

    static Stream<Arguments> damage() {
        return Stream.of(
                Arguments.of("unparseable payload JSON", "UPDATE events SET payload = '{broken' WHERE seq = 2"),
                Arguments.of("NULL field_hashes", "UPDATE events SET field_hashes = NULL WHERE seq = 2"),
                Arguments.of("unparseable salts JSON", "UPDATE events SET salts = 'not json' WHERE seq = 2"),
                Arguments.of("NULL event_type", "UPDATE events SET event_type = NULL WHERE seq = 2"),
                Arguments.of("salt that is not hex", "UPDATE events SET salts = json_set(salts, '$.n', 'zz') WHERE seq = 2"));
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("damage")
    void damagedRowIsReportedAsCorruptRecord(String name, String sql) throws Exception {
        seed(3);
        tamper(sql);
        Response v = verify();
        assertThat(v.status()).isEqualTo(200);
        assertThat(v.<Boolean>get("valid")).isFalse();
        assertThat(v.<String>get("violation")).isEqualTo("CORRUPT_RECORD");
        assertThat(v.<Integer>get("firstInvalidSeq")).isEqualTo(2);
    }

    @Test
    void queriesKeepWorkingWithACorruptRow() throws Exception {
        seed(3);
        tamper("UPDATE events SET payload = '{broken' WHERE seq = 2");
        Response page = get("/audit/events");
        assertThat(page.status()).isEqualTo(200);
        assertThat(page.items()).extracting(m -> m.get("seq")).containsExactly(1, 2, 3);
        assertThat(page.items().get(1).get("payload")).isNull();
    }

    @Test
    void complianceReportSurvivesACorruptRow() throws Exception {
        post("/audit/events", Map.of("eventType", "ACCOUNT_VIEWED", "actorId", "emp-1",
                "resourceType", "CLIENT_ACCOUNT", "resourceId", "acc-1", "payload", Map.of("purpose", "call")));
        tamper("UPDATE events SET payload = '{broken' WHERE seq = 1");
        Response r = post("/audit/reports/account-access", Map.of("accountId", "acc-1"));
        assertThat(r.status()).isEqualTo(200);
        assertThat(r.<Map<String, Object>>get("integrity")).containsEntry("violation", "CORRUPT_RECORD");
    }

    @Test
    void hugeRetentionWindowIsA400NotA500() throws Exception {
        assertThat(post("/audit/retention/run", Map.of("olderThanDays", 1e300)).status()).isEqualTo(400);
        assertThat(post("/audit/retention/run", Map.of("olderThanDays", 36_501)).status()).isEqualTo(400);
    }
}
