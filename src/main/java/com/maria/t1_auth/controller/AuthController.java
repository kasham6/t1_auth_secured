package com.maria.t1_auth.controller;

import com.maria.t1_auth.dto.AuthResponse;
import com.maria.t1_auth.dto.LoginRequest;
import com.maria.t1_auth.dto.RegistryRequest;
import com.maria.t1_auth.service.AuthService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private final AuthService authService;

    @Autowired
    public AuthController(AuthService authService) {
        this.authService = authService;
    }

    @PostMapping("/signup")
    public ResponseEntity<AuthResponse> signUp(@RequestBody RegistryRequest registryRequest) {
        return ResponseEntity.ok(authService.signUp(registryRequest));
    }

    @PostMapping("/login")
    public ResponseEntity<AuthResponse> logIn(@RequestBody LoginRequest loginRequest) {
        return ResponseEntity.ok(authService.logIn(loginRequest));
    }


    @PostMapping("/refresh")
    public ResponseEntity<AuthResponse> refresh(@RequestBody String refreshToken) {
        return ResponseEntity.ok(authService.refreshAccessToken(refreshToken));
    }

    @PostMapping("/logout")
    public ResponseEntity<Void> logout(@RequestBody String refreshToken) {
        authService.logout(refreshToken);
        return ResponseEntity.noContent().build();
    }
}
