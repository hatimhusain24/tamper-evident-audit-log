package com.audit.security;

import java.time.Clock;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.Function;
import java.util.stream.Collectors;
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
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.intercept.AuthorizationFilter;
import org.springframework.security.web.context.SecurityContextHolderFilter;

/**
 * Deny-by-default access control (Spring Security). Callers authenticate with an OAuth2 access
 * token (JWT from an OIDC identity provider, the production mode) and/or HTTP Basic (configured
 * users, for local use). Roles:
 * <ul>
 *   <li>WRITER: append events</li>
 *   <li>READER: query and verify, limited to its resource scopes (sensitive fields masked)</li>
 *   <li>COMPLIANCE: everything READER can, unmasked, plus export and access reports</li>
 *   <li>ADMIN: redaction, retention and checkpoints, plus query and verify (no bulk export)</li>
 * </ul>
 * Identity lives only here and in {@link ResourceScopes}; the chain package knows nothing about it.
 */
@Configuration
@EnableConfigurationProperties(AuditSecurityProperties.class)
public class SecurityConfig {

    static final Set<String> ROLES = Set.of("WRITER", "READER", "COMPLIANCE", "ADMIN");
    private static final Logger SECURITY_LOG = LoggerFactory.getLogger("audit.security");

    @Bean
    SecurityFilterChain filterChain(HttpSecurity http, Clock clock, AuditSecurityProperties props,
                                    @Value("${audit.max-request-bytes:65536}") long maxRequestBytes,
                                    @Value("${audit.rate-limit.per-minute:600}") int perMinute,
                                    @Value("${audit.trusted-proxies:}") Set<String> trustedProxies) throws Exception {
        props.validate();
        http
            // limits run before any authentication, so floods and credential guessing are throttled
            .addFilterAfter(new RequestGuardFilter(maxRequestBytes, perMinute, clock, trustedProxies),
                    SecurityContextHolderFilter.class)
            .addFilterBefore(new LogContextFilter(), AuthorizationFilter.class)
            // Stateless JSON API: no sessions or cookies, and every POST must be application/json,
            // which a cross-site form cannot send (tested in SecurityTest).
            .csrf(csrf -> csrf.disable())
            .sessionManagement(s -> s.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
            .authorizeHttpRequests(auth -> auth
                .requestMatchers(HttpMethod.GET, "/actuator/health").permitAll()   // status only, no details
                .requestMatchers(HttpMethod.GET, "/v1/audit/signing-key").permitAll()   // a public key
                .requestMatchers("/docs", "/swagger-ui/**", "/v3/api-docs/**").permitAll() // off in prod
                .requestMatchers(HttpMethod.POST, "/v1/audit/events").hasRole("WRITER")
                .requestMatchers(HttpMethod.GET, "/v1/audit/events", "/v1/audit/verify")
                    .hasAnyRole("READER", "COMPLIANCE", "ADMIN")
                .requestMatchers(HttpMethod.GET, "/v1/audit/export").hasRole("COMPLIANCE")   // raw PII + salts
                .requestMatchers(HttpMethod.POST, "/v1/audit/reports/account-access").hasRole("COMPLIANCE")
                .requestMatchers(HttpMethod.POST, "/v1/audit/events/*/redactions", "/v1/audit/retention/run",
                        "/v1/audit/checkpoints")
                    .hasRole("ADMIN")
                .requestMatchers(HttpMethod.GET, "/actuator/**").hasRole("ADMIN")
                .anyRequest().denyAll());
        if (props.jwtEnabled()) {
            http.oauth2ResourceServer(oauth -> oauth.jwt(jwt -> jwt
                    .decoder(JwtSupport.decoder(props.jwt()))
                    .jwtAuthenticationConverter(JwtSupport.converter())));
        }
        if (props.basicEnabled()) {
            http.httpBasic(basic -> { });
        }
        return http.build();
    }

    /** The startup checks of {@link #filterChain}, callable without a web context (tests). */
    public void filterChainCheck(AuditSecurityProperties props) {
        props.validate();
        if (props.jwtEnabled()) {
            JwtSupport.decoder(props.jwt());
        }
    }

    @Bean
    PasswordEncoder passwordEncoder() {
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }

    /**
     * Configured users for Basic mode. Fails at startup (no silent open mode) when Basic is enabled
     * without users, or a user has a plaintext password, unknown roles, or is a READER without
     * resource scopes. A password past its {@code password-expires-at} is rejected at login.
     */
    @Bean
    public UserDetailsService users(AuditSecurityProperties properties, Clock clock) {
        List<AuditSecurityProperties.ApiUser> users = properties.users() == null ? List.of() : properties.users();
        if (properties.basicEnabled() && users.isEmpty()) {
            throw new IllegalStateException("No API users configured (audit.security.users) but Basic "
                    + "authentication is enabled. The service refuses to start without access control.");
        }
        users.forEach(SecurityConfig::validate);
        Map<String, AuditSecurityProperties.ApiUser> byName = users.stream()
                .collect(Collectors.toUnmodifiableMap(AuditSecurityProperties.ApiUser::name, Function.identity()));
        return username -> {
            AuditSecurityProperties.ApiUser u = byName.get(username);
            if (u == null) {
                throw new UsernameNotFoundException("unknown user");
            }
            boolean expired = u.passwordExpiresAt() != null && !clock.instant().isBefore(u.passwordExpiresAt());
            return User.withUsername(u.name()).password(u.passwordHash()).roles(u.roles().toArray(String[]::new))
                    .credentialsExpired(expired).build();
        };
    }

    private static void validate(AuditSecurityProperties.ApiUser u) {
        if (u.passwordHash() == null || !u.passwordHash().startsWith("{bcrypt}")) {
            throw new IllegalStateException("User " + u.name() + " must have a {bcrypt} password hash");
        }
        if (u.roles() == null || u.roles().isEmpty() || !ROLES.containsAll(u.roles())) {
            throw new IllegalStateException("User " + u.name() + " has missing or unknown roles " + u.roles());
        }
        boolean readerOnly = u.roles().contains("READER") && !u.roles().contains("COMPLIANCE")
                && !u.roles().contains("ADMIN");
        if (readerOnly && (u.resourceScopes() == null || u.resourceScopes().isEmpty())) {
            throw new IllegalStateException("READER " + u.name() + " must declare resource-scopes "
                    + "(least privilege: readers never see every client's data)");
        }
    }

    /** Per-user resource scopes for Basic users; token users carry theirs in the resource_scopes claim. */
    @Bean
    public ResourceScopes resourceScopes(AuditSecurityProperties properties) {
        return ResourceScopes.from(properties.users() == null ? List.of() : properties.users());
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
