package com.audit.security;

import java.util.List;
import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * API callers, one entry per service or person. Passwords are stored only as bcrypt hashes.
 *
 * <pre>
 * audit.security.users[0].name=ingest-service
 * audit.security.users[0].password-hash={bcrypt}$2a$10$...
 * audit.security.users[0].roles=WRITER
 * </pre>
 */
@ConfigurationProperties("audit.security")
public record AuditSecurityProperties(List<ApiUser> users) {

    public record ApiUser(String name, String passwordHash, List<String> roles) {
    }
}
