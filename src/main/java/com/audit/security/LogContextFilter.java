package com.audit.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.UUID;
import org.slf4j.MDC;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * Adds the authenticated user and a request id to every log line of the request (MDC), so the
 * structured JSON logs can be correlated per user and per request. The id is echoed back in the
 * X-Request-Id response header.
 */
public final class LogContextFilter extends OncePerRequestFilter {

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        String requestId = UUID.randomUUID().toString();
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        MDC.put("request.id", requestId);
        MDC.put("user.name", auth == null ? "anonymous" : LogSafe.clean(auth.getName()));
        response.setHeader("X-Request-Id", requestId);
        try {
            chain.doFilter(request, response);
        } finally {
            MDC.remove("request.id");
            MDC.remove("user.name");
        }
    }
}
