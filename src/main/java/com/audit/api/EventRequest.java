package com.audit.api;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import java.util.Map;

/** Caller-supplied event. The timestamp is assigned by the server; unknown fields are rejected. */
public record EventRequest(
        @Schema(example = "ACCOUNT_VIEWED")
        @NotBlank @Pattern(regexp = "^[A-Z][A-Z0-9_]{1,63}$", message = "must be UPPER_SNAKE_CASE")
        String eventType,
        @Schema(example = "emp-1") @NotBlank @Size(max = 128) String actorId,
        @Schema(example = "CLIENT_ACCOUNT") @NotBlank @Size(max = 128) String resourceType,
        @Schema(example = "acc-1001") @NotBlank @Size(max = 128) String resourceId,
        @Schema(example = "{\"purpose\": \"client call\", \"accountNumber\": \"9876543210\"}")
        Map<String, Object> payload) {
}
