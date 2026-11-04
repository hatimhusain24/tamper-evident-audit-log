package com.audit.api;

import com.audit.store.AuditStore;
import org.springframework.http.HttpStatus;
import org.springframework.http.ProblemDetail;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

/** Maps store errors to HTTP. Validation errors return 400 via Spring's ProblemDetail support. */
@RestControllerAdvice
public class ApiErrors {

    @ExceptionHandler(AuditStore.NotFound.class)
    ProblemDetail notFound(AuditStore.NotFound e) {
        return ProblemDetail.forStatusAndDetail(HttpStatus.NOT_FOUND, e.getMessage());
    }

    @ExceptionHandler(AuditStore.Conflict.class)
    ProblemDetail conflict(AuditStore.Conflict e) {
        return ProblemDetail.forStatusAndDetail(HttpStatus.CONFLICT, e.getMessage());
    }
}
