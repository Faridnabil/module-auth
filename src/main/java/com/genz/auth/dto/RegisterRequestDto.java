package com.genz.auth.dto;

import lombok.Data;

@Data
public class RegisterRequestDto {
    private String username;
    private String password;
    private String email;
    private String role;
}