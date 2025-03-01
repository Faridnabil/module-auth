package com.genz.auth.exception;

import com.genz.auth.common.ApiResponse;
import jakarta.ws.rs.ForbiddenException;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.ext.ExceptionMapper;
import jakarta.ws.rs.ext.Provider;

@Provider
public class ForbiddenExceptionMapper implements ExceptionMapper<ForbiddenException> {

    @Override
    public Response toResponse(ForbiddenException exception) {
        ApiResponse<?> apiResponse = ApiResponse.error("Forbidden: " + exception.getMessage());
        return Response.status(Response.Status.FORBIDDEN)
                .entity(apiResponse)
                .build();
    }
}