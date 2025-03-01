package com.genz.auth.dto;

import lombok.Data;

@Data
public class AuthResponseDto {
    private String username;
    private String role;
    private String token;
}
