package com.audit.security;

import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * Per-user resource scopes (protection against IDOR / broken object-level authorization).
 * A scope is {@code TYPE:ID} where TYPE is a resource type or {@code *}, and ID is an exact id or a
 * prefix ending in {@code *}. Examples: {@code CLIENT_ACCOUNT:acc-1*}, {@code SESSION:*}.
 * A user with no scopes is unrestricted; READER users must always declare scopes.
 */
public final class ResourceScopes {

    /** One parsed scope. */
    public record Scope(String type, String idPrefix, boolean exactId) {

        static Scope parse(String text) {
            String[] parts = text == null ? new String[0] : text.trim().split(":", 2);
            if (parts.length != 2 || parts[0].isEmpty() || parts[1].isEmpty()
                    || parts[1].indexOf('*') >= 0 && parts[1].indexOf('*') != parts[1].length() - 1
                    || parts[0].contains("*") && !parts[0].equals("*")) {
                throw new IllegalStateException("resource scope '" + text + "' must look like TYPE:ID, TYPE:PREFIX* or *:*");
            }
            boolean prefix = parts[1].endsWith("*");
            return new Scope(parts[0], prefix ? parts[1].substring(0, parts[1].length() - 1) : parts[1], !prefix);
        }

        public boolean matches(String resourceType, String resourceId) {
            boolean typeOk = "*".equals(type) || type.equals(resourceType);
            boolean idOk = exactId ? idPrefix.equals(resourceId) : resourceId != null && resourceId.startsWith(idPrefix);
            return typeOk && idOk;
        }
    }

    private final Map<String, List<Scope>> byUser;

    private ResourceScopes(Map<String, List<Scope>> byUser) {
        this.byUser = byUser;
    }

    static ResourceScopes from(List<AuditSecurityProperties.ApiUser> users) {
        return new ResourceScopes(users.stream().collect(Collectors.toUnmodifiableMap(
                AuditSecurityProperties.ApiUser::name,
                u -> u.resourceScopes() == null ? List.of() : u.resourceScopes().stream().map(Scope::parse).toList())));
    }

    /** Empty list = unrestricted. */
    public List<Scope> of(String user) {
        return byUser.getOrDefault(user, List.of());
    }

    public boolean unrestricted(String user) {
        return of(user).isEmpty();
    }

    public boolean allows(String user, String resourceType, String resourceId) {
        List<Scope> scopes = of(user);
        return scopes.isEmpty() || scopes.stream().anyMatch(s -> s.matches(resourceType, resourceId));
    }
}
