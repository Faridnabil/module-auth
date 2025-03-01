package com.genz.auth.exception;

import com.genz.auth.common.ApiResponse;
import jakarta.ws.rs.NotAuthorizedException;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.ext.ExceptionMapper;
import jakarta.ws.rs.ext.Provider;

@Provider
public class UnauthorizedExceptionMapper implements ExceptionMapper<NotAuthorizedException> {

    @Override
    public Response toResponse(NotAuthorizedException exception) {
        ApiResponse<?> apiResponse = ApiResponse.error("Unauthorized: " + exception.getMessage());
        return Response.status(Response.Status.UNAUTHORIZED)
                .entity(apiResponse)
                .build();
    }
}