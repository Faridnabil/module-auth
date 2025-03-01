package com.genz.auth.resource;

import com.genz.auth.common.ApiResponse;
import com.genz.auth.dto.LoginRequestDto;
import com.genz.auth.dto.RegisterRequestDto;
import com.genz.auth.service.AuthService;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import lombok.RequiredArgsConstructor;
import io.smallrye.mutiny.Uni;

@Path("/auth")
@Produces(MediaType.APPLICATION_JSON)
@Consumes(MediaType.APPLICATION_JSON)
@RequiredArgsConstructor
public class AuthResource {

    private final AuthService authService;

    @POST
    @Path("/register")
    public Uni<Response> register(RegisterRequestDto registerRequestDto) {
        return authService.register(registerRequestDto)
                .onItem().transform(response -> Response.ok(ApiResponse.ok(response)).build())
                .onFailure().recoverWithItem(error -> Response.status(Response.Status.BAD_REQUEST)
                        .entity(ApiResponse.badRequest(error.getMessage())).build());
    }

    @POST
    @Path("/login")
    public Uni<Response> login(LoginRequestDto loginRequestDto) {
        return authService.login(loginRequestDto)
                .onItem().transform(response -> Response.ok(ApiResponse.ok(response)).build())
                .onFailure().recoverWithItem(error -> Response.status(Response.Status.UNAUTHORIZED)
                        .entity(ApiResponse.error(error.getMessage())).build());
    }

    @GET
    @Path("/validate")
    public Response validateToken() {
        return Response.ok("Token is valid").build();
    }
}