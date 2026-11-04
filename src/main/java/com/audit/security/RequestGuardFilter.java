package com.audit.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ReadListener;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletInputStream;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletRequestWrapper;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.time.Clock;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * Runs before authentication:
 * <ul>
 *   <li>Rate limit per client IP (fixed one-minute window), so floods and password guessing are
 *       throttled with HTTP 429 before any expensive work. Behind a load balancer the client IP
 *       comes from X-Forwarded-For, but only when the request arrives from a configured trusted
 *       proxy; anyone else's X-Forwarded-For is ignored, so it can't be used to dodge the limit.</li>
 *   <li>Request body limit: an oversized declared body is refused with 413 before it is read;
 *       a body without a declared length is cut off as soon as it passes the limit.</li>
 * </ul>
 */
public final class RequestGuardFilter extends OncePerRequestFilter {

    private static final Logger SECURITY_LOG = LoggerFactory.getLogger("audit.security");
    private static final int MAX_TRACKED_CLIENTS = 10_000;

    /** Thrown while reading a body that exceeds the limit; mapped to HTTP 413. */
    public static final class BodyTooLarge extends IOException {
        public BodyTooLarge(long limit) {
            super("request body exceeds " + limit + " bytes");
        }
    }

    private record Window(long minute, AtomicInteger count) {
    }

    private final long maxBodyBytes;
    private final int requestsPerMinute;
    private final Clock clock;
    private final Set<String> trustedProxies;
    private final Map<String, Window> windows = new ConcurrentHashMap<>();

    public RequestGuardFilter(long maxBodyBytes, int requestsPerMinute, Clock clock, Set<String> trustedProxies) {
        this.maxBodyBytes = maxBodyBytes;
        this.requestsPerMinute = requestsPerMinute;
        this.clock = clock;
        this.trustedProxies = Set.copyOf(trustedProxies);
    }

    /** The rightmost X-Forwarded-For address that is not a trusted proxy, if the caller is one. */
    String clientIp(HttpServletRequest request) {
        String remote = request.getRemoteAddr();
        String forwarded = request.getHeader("X-Forwarded-For");
        if (!trustedProxies.contains(remote) || forwarded == null) {
            return remote;
        }
        String[] hops = forwarded.split(",");
        for (int i = hops.length - 1; i >= 0; i--) {
            String hop = hops[i].trim();
            if (!hop.isEmpty() && !trustedProxies.contains(hop)) {
                return hop;
            }
        }
        return remote;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        String client = clientIp(request);
        if (!allow(client)) {
            SECURITY_LOG.warn("rate limit exceeded client={}", LogSafe.clean(client));
            response.setHeader("Retry-After", "60");
            problem(response, 429, "rate limit of " + requestsPerMinute + " requests per minute exceeded");
            return;
        }
        if (request.getContentLengthLong() > maxBodyBytes) {
            problem(response, 413, "request body exceeds " + maxBodyBytes + " bytes");
            return;
        }
        chain.doFilter(new LimitedRequest(request, maxBodyBytes), response);
    }

    private boolean allow(String client) {
        long minute = clock.millis() / 60_000;
        if (windows.size() > MAX_TRACKED_CLIENTS) {
            windows.clear();   // bounded memory; worst case a client gets a fresh window
        }
        Window w = windows.compute(client, (k, old) ->
                old == null || old.minute() != minute ? new Window(minute, new AtomicInteger()) : old);
        return w.count().incrementAndGet() <= requestsPerMinute;
    }

    private static void problem(HttpServletResponse response, int status, String detail) throws IOException {
        response.setStatus(status);
        response.setContentType("application/problem+json");
        response.getWriter().write("{\"status\":" + status + ",\"detail\":\"" + detail + "\"}");
    }

    /** Counts body bytes as they are read and stops at the limit. */
    private static final class LimitedRequest extends HttpServletRequestWrapper {
        private final long limit;

        LimitedRequest(HttpServletRequest request, long limit) {
            super(request);
            this.limit = limit;
        }

        @Override
        public ServletInputStream getInputStream() throws IOException {
            ServletInputStream in = super.getInputStream();
            return new ServletInputStream() {
                private long read;

                private int count(int n) throws IOException {
                    if (n > 0 && (read += n) > limit) {
                        throw new BodyTooLarge(limit);
                    }
                    return n;
                }

                @Override
                public int read() throws IOException {
                    int b = in.read();
                    if (b >= 0) {
                        count(1);
                    }
                    return b;
                }

                @Override
                public int read(byte[] buf, int off, int len) throws IOException {
                    return count(in.read(buf, off, len));
                }

                @Override
                public boolean isFinished() {
                    return in.isFinished();
                }

                @Override
                public boolean isReady() {
                    return in.isReady();
                }

                @Override
                public void setReadListener(ReadListener listener) {
                    in.setReadListener(listener);
                }
            };
        }
    }
}
