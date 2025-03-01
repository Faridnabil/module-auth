package com.genz.auth.exception;

import com.genz.auth.common.ApiResponse;
import jakarta.ws.rs.NotFoundException;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.ext.ExceptionMapper;
import jakarta.ws.rs.ext.Provider;

@Provider
public class NotFoundExceptionMapper implements ExceptionMapper<NotFoundException> {

    @Override
    public Response toResponse(NotFoundException exception) {
        ApiResponse<?> apiResponse = ApiResponse.notFound(exception.getMessage());
        return Response.status(Response.Status.NOT_FOUND)
                .entity(apiResponse)
                .build();
    }
}