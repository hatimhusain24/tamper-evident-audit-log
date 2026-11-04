package com.audit.security;

import java.time.Clock;
import java.util.List;
import java.util.Set;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.event.EventListener;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.event.AbstractAuthenticationFailureEvent;
import org.springframework.security.authorization.event.AuthorizationDeniedEvent;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

/**
 * Deny-by-default access control. Every caller authenticates (HTTP Basic, stateless) as a named
 * user with one or more roles:
 * <ul>
 *   <li>WRITER: append events</li>
 *   <li>READER: query and verify (sensitive payload fields masked)</li>
 *   <li>COMPLIANCE: everything READER can, unmasked, plus export and access reports</li>
 *   <li>ADMIN: redaction and retention, plus query and verify (no bulk export)</li>
 * </ul>
 * Swapping Basic for OAuth2/OIDC tokens only changes this class.
 */
@Configuration
@EnableConfigurationProperties(AuditSecurityProperties.class)
public class SecurityConfig {

    static final Set<String> ROLES = Set.of("WRITER", "READER", "COMPLIANCE", "ADMIN");
    private static final Logger SECURITY_LOG = LoggerFactory.getLogger("audit.security");

    @Bean
    SecurityFilterChain filterChain(HttpSecurity http, Clock clock,
                                    @Value("${audit.max-request-bytes:65536}") long maxRequestBytes,
                                    @Value("${audit.rate-limit.per-minute:600}") int perMinute) throws Exception {
        http
            .addFilterBefore(new RequestGuardFilter(maxRequestBytes, perMinute, clock), BasicAuthenticationFilter.class)
            // Stateless JSON API: no sessions or cookies, and every POST must be application/json,
            // which a cross-site form cannot send (tested in SecurityTest).
            .csrf(csrf -> csrf.disable())
            .sessionManagement(s -> s.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
            .httpBasic(basic -> { })
            .authorizeHttpRequests(auth -> auth
                .requestMatchers(HttpMethod.GET, "/actuator/health").permitAll()   // status only, no details
                .requestMatchers("/docs", "/swagger-ui/**", "/v3/api-docs/**").permitAll() // off in prod
                .requestMatchers(HttpMethod.POST, "/v1/audit/events").hasRole("WRITER")
                .requestMatchers(HttpMethod.GET, "/v1/audit/events", "/v1/audit/verify")
                    .hasAnyRole("READER", "COMPLIANCE", "ADMIN")
                .requestMatchers(HttpMethod.GET, "/v1/audit/export").hasRole("COMPLIANCE")   // raw PII + salts
                .requestMatchers(HttpMethod.POST, "/v1/audit/reports/account-access").hasRole("COMPLIANCE")
                .requestMatchers(HttpMethod.POST, "/v1/audit/events/*/redactions", "/v1/audit/retention/run")
                    .hasRole("ADMIN")
                .requestMatchers(HttpMethod.GET, "/actuator/**").hasRole("ADMIN")
                .anyRequest().denyAll());
        return http.build();
    }

    @Bean
    PasswordEncoder passwordEncoder() {
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }

    /** Fails at startup (no silent open mode) when no users, a plaintext password or an unknown role is configured. */
    @Bean
    public UserDetailsService users(AuditSecurityProperties properties) {
        List<AuditSecurityProperties.ApiUser> users = properties.users();
        if (users == null || users.isEmpty()) {
            throw new IllegalStateException("No API users configured (audit.security.users). "
                    + "The service refuses to start without access control.");
        }
        List<UserDetails> details = users.stream().map(u -> {
            if (u.passwordHash() == null || !u.passwordHash().startsWith("{bcrypt}")) {
                throw new IllegalStateException("User " + u.name() + " must have a {bcrypt} password hash");
            }
            if (u.roles() == null || u.roles().isEmpty() || !ROLES.containsAll(u.roles())) {
                throw new IllegalStateException("User " + u.name() + " has missing or unknown roles " + u.roles());
            }
            return User.withUsername(u.name()).password(u.passwordHash())
                    .roles(u.roles().toArray(String[]::new)).build();
        }).toList();
        return new InMemoryUserDetailsManager(details);
    }

    @EventListener
    public void onAuthenticationFailure(AbstractAuthenticationFailureEvent event) {
        SECURITY_LOG.warn("authentication failed user={} reason={}",
                LogSafe.clean(event.getAuthentication().getName()), event.getException().getClass().getSimpleName());
    }

    @EventListener
    public void onAccessDenied(AuthorizationDeniedEvent<?> event) {
        var auth = event.getAuthentication().get();
        if (auth != null && auth.isAuthenticated() && !"anonymousUser".equals(auth.getName())) {
            SECURITY_LOG.warn("access denied user={}", LogSafe.clean(auth.getName()));
        }
    }
}
