package com.audit.security;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.time.Clock;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

/** Paths MockMvc can't reach: a body sent without Content-Length (chunked), and log sanitizing. */
class RequestGuardFilterTest {

    /** A chunked request: the body is there, but its length is not declared. */
    static MockHttpServletRequest chunked(int bytes) {
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/audit/events") {
            @Override
            public long getContentLengthLong() {
                return -1;
            }
        };
        request.setContent(new byte[bytes]);
        return request;
    }

    @Test
    void undeclaredBodyIsCutOffOnceItPassesTheLimit() {
        RequestGuardFilter filter = new RequestGuardFilter(1024, 100, Clock.systemUTC());
        assertThatThrownBy(() -> filter.doFilter(chunked(4096), new MockHttpServletResponse(),
                (req, res) -> req.getInputStream().readAllBytes()))
                .isInstanceOf(RequestGuardFilter.BodyTooLarge.class)
                .hasMessageContaining("1024");
    }

    @Test
    void undeclaredBodyWithinTheLimitIsReadNormally() throws Exception {
        RequestGuardFilter filter = new RequestGuardFilter(1024, 100, Clock.systemUTC());
        int[] read = new int[1];
        filter.doFilter(chunked(1000), new MockHttpServletResponse(), (req, res) -> {
            var in = req.getInputStream();
            read[0] = in.read() >= 0 ? 1 : 0;                       // single-byte read path
            read[0] += in.readAllBytes().length;
        });
        assertThat(read[0]).isEqualTo(1000);
    }

    @Test
    void logValuesAreFlattenedAndBounded() {
        assertThat(LogSafe.clean("alice\nFAKE ENTRY\r")).isEqualTo("alice_FAKE ENTRY_");
        assertThat(LogSafe.clean("x".repeat(500))).hasSize(131).endsWith("...");
        assertThat(LogSafe.clean(null)).isEqualTo("null");
    }
}
