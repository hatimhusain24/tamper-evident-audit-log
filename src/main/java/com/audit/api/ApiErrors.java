package com.audit.api;

import com.audit.security.RequestGuardFilter;
import com.audit.store.AuditStore;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.dao.DataAccessException;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.http.ProblemDetail;
import org.springframework.transaction.TransactionException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.context.request.WebRequest;
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

    /** A body cut off by RequestGuardFilter surfaces as unreadable JSON: report it as 413. */
    @Override
    protected ResponseEntity<Object> handleHttpMessageNotReadable(HttpMessageNotReadableException ex,
            HttpHeaders headers, HttpStatusCode status, WebRequest request) {
        for (Throwable t = ex; t != null; t = t.getCause()) {
            if (t instanceof RequestGuardFilter.BodyTooLarge) {
                return ResponseEntity.status(HttpStatus.CONTENT_TOO_LARGE)
                        .body(ProblemDetail.forStatusAndDetail(HttpStatus.CONTENT_TOO_LARGE, t.getMessage()));
            }
        }
        return super.handleHttpMessageNotReadable(ex, headers, status, request);
    }

    /** Database busy (another writer holds the lock past the timeout): a retryable 503, not a 500. */
    @ExceptionHandler({DataAccessException.class, TransactionException.class})
    ResponseEntity<ProblemDetail> database(RuntimeException e) {
        for (Throwable t = e; t != null; t = t.getCause()) {
            if (t.getMessage() != null && t.getMessage().contains("SQLITE_BUSY")) {
                LOG.warn("database busy, request rejected for retry");
                return ResponseEntity.status(HttpStatus.SERVICE_UNAVAILABLE).header(HttpHeaders.RETRY_AFTER, "1")
                        .body(ProblemDetail.forStatusAndDetail(HttpStatus.SERVICE_UNAVAILABLE, "database busy, retry"));
            }
        }
        return ResponseEntity.internalServerError().body(unexpected(e));
    }

    @ExceptionHandler(Exception.class)
    ProblemDetail unexpected(Exception e) {
        LOG.error("unhandled error", e);
        return ProblemDetail.forStatusAndDetail(HttpStatus.INTERNAL_SERVER_ERROR, "internal error");
    }
}
