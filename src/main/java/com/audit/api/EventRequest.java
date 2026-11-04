package com.audit.api;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import java.util.Map;

/** Caller-supplied event. The timestamp is assigned by the server; unknown fields are rejected. */
public record EventRequest(
        @NotBlank @Pattern(regexp = "^[A-Z][A-Z0-9_]{1,63}$", message = "must be UPPER_SNAKE_CASE")
        String eventType,
        @NotBlank @Size(max = 128) String actorId,
        @NotBlank @Size(max = 128) String resourceType,
        @NotBlank @Size(max = 128) String resourceId,
        Map<String, Object> payload) {
}
