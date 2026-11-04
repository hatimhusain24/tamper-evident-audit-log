package com.audit.security;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.time.Clock;
import java.util.Set;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

/** Paths MockMvc can't reach: a body sent without Content-Length (chunked), and log sanitizing. */
class RequestGuardFilterTest {

    /** A chunked request: the body is there, but its length is not declared. */
    static MockHttpServletRequest chunked(int bytes) {
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/v1/audit/events") {
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
        RequestGuardFilter filter = new RequestGuardFilter(1024, 100, Clock.systemUTC(), Set.of());
        assertThatThrownBy(() -> filter.doFilter(chunked(4096), new MockHttpServletResponse(),
                (req, res) -> req.getInputStream().readAllBytes()))
                .isInstanceOf(RequestGuardFilter.BodyTooLarge.class)
                .hasMessageContaining("1024");
    }

    @Test
    void undeclaredBodyWithinTheLimitIsReadNormally() throws Exception {
        RequestGuardFilter filter = new RequestGuardFilter(1024, 100, Clock.systemUTC(), Set.of());
        int[] read = new int[1];
        filter.doFilter(chunked(1000), new MockHttpServletResponse(), (req, res) -> {
            var in = req.getInputStream();
            read[0] = in.read() >= 0 ? 1 : 0;                       // single-byte read path
            read[0] += in.readAllBytes().length;
        });
        assertThat(read[0]).isEqualTo(1000);
    }

    static MockHttpServletRequest from(String remote, String forwardedFor) {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/v1/audit/verify");
        request.setRemoteAddr(remote);
        if (forwardedFor != null) {
            request.addHeader("X-Forwarded-For", forwardedFor);
        }
        return request;
    }

    static int status(RequestGuardFilter filter, MockHttpServletRequest request) throws Exception {
        MockHttpServletResponse response = new MockHttpServletResponse();
        filter.doFilter(request, response, (req, res) -> { });
        return response.getStatus();
    }

    @Test
    void clientsBehindATrustedProxyGetTheirOwnLimit() throws Exception {
        RequestGuardFilter filter = new RequestGuardFilter(1024, 1, Clock.systemUTC(), Set.of("10.0.0.1"));
        assertThat(status(filter, from("10.0.0.1", "203.0.113.5"))).isEqualTo(200);
        assertThat(status(filter, from("10.0.0.1", "198.51.100.7"))).isEqualTo(200);   // different client
        assertThat(status(filter, from("10.0.0.1", "203.0.113.5"))).isEqualTo(429);    // same client again
    }

    @Test
    void forwardedForFromAnUntrustedCallerIsIgnored() throws Exception {
        RequestGuardFilter filter = new RequestGuardFilter(1024, 1, Clock.systemUTC(), Set.of("10.0.0.1"));
        assertThat(status(filter, from("192.0.2.9", "1.1.1.1"))).isEqualTo(200);
        assertThat(status(filter, from("192.0.2.9", "2.2.2.2"))).isEqualTo(429);       // spoofing doesn't help
    }

    @Test
    void rightmostUntrustedHopIsTheClient() {
        RequestGuardFilter filter = new RequestGuardFilter(1024, 1, Clock.systemUTC(), Set.of("10.0.0.1", "10.0.0.2"));
        assertThat(filter.clientIp(from("10.0.0.1", "6.6.6.6, 203.0.113.5, 10.0.0.2"))).isEqualTo("203.0.113.5");
        assertThat(filter.clientIp(from("10.0.0.1", "10.0.0.2"))).isEqualTo("10.0.0.1");   // only proxies
        assertThat(filter.clientIp(from("10.0.0.1", null))).isEqualTo("10.0.0.1");
        assertThat(filter.clientIp(from("10.0.0.1", " , "))).isEqualTo("10.0.0.1");
    }

    @Test
    void logValuesAreFlattenedAndBounded() {
        assertThat(LogSafe.clean("alice\nFAKE ENTRY\r")).isEqualTo("alice_FAKE ENTRY_");
        assertThat(LogSafe.clean("x".repeat(500))).hasSize(131).endsWith("...");
        assertThat(LogSafe.clean(null)).isEqualTo("null");
    }
}
