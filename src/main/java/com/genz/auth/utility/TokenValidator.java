package com.genz.auth.utility;

import io.smallrye.jwt.auth.principal.JWTParser;
import io.smallrye.jwt.auth.principal.ParseException;
import io.smallrye.jwt.build.Jwt;
import io.smallrye.jwt.build.JwtClaimsBuilder;

import org.eclipse.microprofile.config.inject.ConfigProperty;
import org.eclipse.microprofile.jwt.JsonWebToken;

import jakarta.enterprise.context.ApplicationScoped;
import lombok.RequiredArgsConstructor;

import java.util.Set;

@ApplicationScoped
@RequiredArgsConstructor
public class TokenValidator {

    private final JWTParser jwtParser;

    @ConfigProperty(name = "jwt.issuer")
    String issuer;

    /**
     * Validasi token JWT.
     *
     * @param token Token JWT yang akan divalidasi.
     * @return Objek JsonWebToken jika token valid.
     * @throws ParseException Jika token tidak valid.
     */
    public JsonWebToken validateToken(String token) throws ParseException {
        return jwtParser.parse(token);
    }

    /**
     * Buat token JWT baru.
     *
     * @param username Username pengguna.
     * @param roles    Roles pengguna.
     * @param email    Email pengguna.
     * @return Token JWT yang sudah ditandatangani.
     */
    public String generateToken(String username, Set<String> roles, String email) {
        JwtClaimsBuilder claimsBuilder = Jwt.claims();
        claimsBuilder.issuer(issuer) // Ganti dengan issuer Anda
                .upn(username)
                .groups(roles)
                .claim("email", email)
                .expiresIn(3600); // Token berlaku selama 1 jam

        return claimsBuilder.sign();
    }
}