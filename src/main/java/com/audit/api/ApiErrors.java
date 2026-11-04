package com.audit.api;

import com.audit.store.AuditStore;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ProblemDetail;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.servlet.mvc.method.annotation.ResponseEntityExceptionHandler;

/**
 * Maps errors to RFC 7807 problem details. Spring's standard exceptions (validation, bad JSON,
 * missing parameters) are handled by the parent class as 400s. Anything unexpected becomes a
 * generic 500 that never leaks a stack trace, and is logged for the operator.
 */
@RestControllerAdvice
public class ApiErrors extends ResponseEntityExceptionHandler {

    private static final Logger LOG = LoggerFactory.getLogger(ApiErrors.class);

    @ExceptionHandler(AuditStore.NotFound.class)
    ProblemDetail notFound(AuditStore.NotFound e) {
        return ProblemDetail.forStatusAndDetail(HttpStatus.NOT_FOUND, e.getMessage());
    }

    @ExceptionHandler(AuditStore.Conflict.class)
    ProblemDetail conflict(AuditStore.Conflict e) {
        return ProblemDetail.forStatusAndDetail(HttpStatus.CONFLICT, e.getMessage());
    }

    @ExceptionHandler(AuditStore.PolicyViolation.class)
    ProblemDetail policy(AuditStore.PolicyViolation e) {
        return ProblemDetail.forStatusAndDetail(HttpStatus.BAD_REQUEST, e.getMessage());
    }

    @ExceptionHandler(Exception.class)
    ProblemDetail unexpected(Exception e) {
        LOG.error("unhandled error", e);
        return ProblemDetail.forStatusAndDetail(HttpStatus.INTERNAL_SERVER_ERROR, "internal error");
    }
}
