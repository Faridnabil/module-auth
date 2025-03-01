package com.genz.auth.service;

import com.genz.auth.dto.AuthResponseDto;
import com.genz.auth.dto.LoginRequestDto;
import com.genz.auth.dto.RegisterRequestDto;
import com.genz.auth.entity.UserEntity;
import com.genz.auth.repository.UserRepository;
import com.genz.auth.utility.TokenValidator;

import io.quarkus.hibernate.reactive.panache.common.WithSession;
import io.smallrye.mutiny.Uni;
import jakarta.enterprise.context.ApplicationScoped;
import lombok.RequiredArgsConstructor;

import java.util.HashSet;
import java.util.Set;

@ApplicationScoped
@RequiredArgsConstructor
public class AuthService {

    private final UserRepository userRepository;

    private final TokenValidator tokenValidator;

    // Register a new user
    @WithSession
    public Uni<AuthResponseDto> register(RegisterRequestDto registerRequestDto) {
        UserEntity user = new UserEntity();
        user.setUsername(registerRequestDto.getUsername());
        user.setPassword(registerRequestDto.getPassword()); // Anda harus mengenkripsi password sebelum menyimpannya
        user.setEmail(registerRequestDto.getEmail());
        user.setRole(registerRequestDto.getRole());

        return userRepository.persist(user)
                .onItem().transform(ignore -> {
                    Set<String> roles = new HashSet<>();
                    roles.add(user.getRole());
                    String token = tokenValidator.generateToken(user.getUsername(), roles, user.getEmail());

                    AuthResponseDto authResponseDto = new AuthResponseDto();
                    authResponseDto.setToken(token);
                    authResponseDto.setUsername(user.getUsername());
                    authResponseDto.setRole(user.getRole());

                    return authResponseDto;
                });
    }

    // Login with username and password
    @WithSession
    public Uni<AuthResponseDto> login(LoginRequestDto loginRequestDto) {
        return userRepository.findByUsername(loginRequestDto.getUsername())
                .onItem().ifNotNull().transform(user -> {
                    if (user.getPassword().equals(loginRequestDto.getPassword())) {
                        Set<String> roles = new HashSet<>();
                        roles.add(user.getRole());
                        String token = tokenValidator.generateToken(user.getUsername(), roles, user.getEmail());

                        AuthResponseDto authResponseDto = new AuthResponseDto();
                        authResponseDto.setToken(token);
                        authResponseDto.setUsername(user.getUsername());
                        authResponseDto.setRole(user.getRole());

                        return authResponseDto;
                    } else {
                        throw new RuntimeException("Invalid username or password");
                    }
                })
                .onItem().ifNull().failWith(() -> new RuntimeException("User not found"));
    }
}