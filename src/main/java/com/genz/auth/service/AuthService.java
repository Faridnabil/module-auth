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

import org.mindrot.jbcrypt.BCrypt;

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

        String hashedPassword = BCrypt.hashpw(registerRequestDto.getPassword(), BCrypt.gensalt());
        user.setPassword(hashedPassword);
        
        user.setEmail(registerRequestDto.getEmail());
        user.setRole(registerRequestDto.getRole());
        user.setStatusAktif(true);

        return userRepository.persist(user)
                .onItem().transform(ignore -> {
                    Set<String> roles = new HashSet<>();
                    roles.add(user.getRole());
                    String token = tokenValidator.generateToken(user.getUsername(), roles, user.getEmail());

                    AuthResponseDto authResponseDto = new AuthResponseDto();
                    authResponseDto.setUsername(user.getUsername());
                    authResponseDto.setRole(user.getRole());
                    authResponseDto.setStatusAktif(user.isStatusAktif());
                    authResponseDto.setToken(token);

                    return authResponseDto;
                });
    }

    // Login with username and password
    @WithSession
    public Uni<AuthResponseDto> login(LoginRequestDto loginRequestDto) {
        return userRepository.findByUsername(loginRequestDto.getUsername())
                .onItem().ifNotNull().transformToUni(user -> {
                    // Validasi password
                    if (BCrypt.checkpw(loginRequestDto.getPassword(), user.getPassword())) {
                        // Jika password valid, generate token
                        Set<String> roles = new HashSet<>();
                        roles.add(user.getRole());
                        String token = tokenValidator.generateToken(user.getUsername(), roles, user.getEmail());

                        // Buat response
                        AuthResponseDto authResponseDto = new AuthResponseDto();
                        authResponseDto.setUsername(user.getUsername());
                        authResponseDto.setRole(user.getRole());
                        authResponseDto.setToken(token);

                        return Uni.createFrom().item(authResponseDto);
                    } else {
                        return Uni.createFrom().failure(new RuntimeException("Invalid username or password"));
                    }
                })
                .onItem().ifNull().failWith(() -> new RuntimeException("User not found"));
    }
}