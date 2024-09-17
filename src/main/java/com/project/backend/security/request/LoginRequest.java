package com.project.backend.security.request;


import lombok.Getter;
import lombok.Setter;

@Setter
@Getter
public class LoginRequest {
    private String username;
    private String email;
    private String password;
};