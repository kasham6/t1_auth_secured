package com.maria.t1_auth.service;

import com.maria.t1_auth.dto.AuthResponse;
import com.maria.t1_auth.dto.LoginRequest;
import com.maria.t1_auth.dto.RegistryRequest;
import com.maria.t1_auth.model.Role;
import com.maria.t1_auth.model.User;
import com.maria.t1_auth.repository.UserRepository;
import com.nimbusds.jwt.JWTClaimsSet;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.util.Set;

@Service
@Slf4j
public class AuthService {

    private final UserRepository userRepository;
    private final JwtService jwtService;
    private final StringRedisTemplate redis;
    private final PasswordEncoder passwordEncoder;

    private static final Duration REFRESH_TTL = Duration.ofDays(7);

    @Autowired
    public AuthService(UserRepository userRepository,
                       JwtService jwtService,
                       StringRedisTemplate redis,
                       PasswordEncoder passwordEncoder) {
        this.userRepository = userRepository;
        this.jwtService = jwtService;
        this.redis = redis;
        this.passwordEncoder = passwordEncoder;
    }

    public AuthResponse signUp(RegistryRequest request) {
        if (userRepository.existsByUsername(request.getUsername())) {
            throw new RuntimeException("Username already taken");
        }
        if (userRepository.existsByEmail(request.getEmail())) {
            throw new RuntimeException("Email already registered");
        }

        String passwordHash = passwordEncoder.encode(request.getPassword());
        User newUser = new User();
        newUser.setUsername(request.getUsername());
        newUser.setEmail(request.getEmail());
        newUser.setPasswordHash(passwordHash);
        newUser.setRoles(Set.of(Role.GUEST));
        userRepository.save(newUser);
        log.info("New user with username {} created", request.getUsername());

        return generateTokens(newUser);
    }

    public AuthResponse logIn(LoginRequest request) {
        User user = userRepository.getUserByUsername(request.getUsername());
        if (!passwordEncoder.matches(request.getPassword(), user.getPasswordHash())) {
            throw new RuntimeException("Invalid credentials");
        }
        log.info("User with username {} logged in", user.getUsername());
        return generateTokens(user);
    }

    public AuthResponse refreshAccessToken(String refreshToken) throws Exception {

        JWTClaimsSet claims = jwtService.parseRefreshToken(refreshToken);
        String jti = claims.getJWTID();

        String userId = redis.opsForValue().get("refresh:" + jti);
        if (userId == null) {
            throw new RuntimeException("Invalid or expired refresh token");
        }

        redis.delete("refresh:" + jti);

        User user = userRepository.findById(Long.parseLong(userId))
                .orElseThrow(() -> new RuntimeException("User not found"));
        return generateTokens(user);
    }

    public void logout(String refreshToken) throws Exception {
        if (refreshToken == null || refreshToken.isBlank()) {
            throw new IllegalArgumentException("Refresh token must be provided");
        }
        JWTClaimsSet claims = jwtService.parseRefreshToken(refreshToken);
        String jti = claims.getJWTID();
        redis.delete("refresh:" + jti);
    }

    private AuthResponse generateTokens(User user) {
        try {
            String accessToken  = jwtService.generateAccessToken(user);
            String refreshToken = jwtService.generateRefreshToken(user);

            JWTClaimsSet claims = jwtService.parseRefreshToken(refreshToken);
            String jti = claims.getJWTID();

            redis.opsForValue()
                    .set("refresh:" + jti,
                            String.valueOf(user.getId()),
                            REFRESH_TTL);

            return new AuthResponse(accessToken, refreshToken);

        } catch (Exception e) {
            throw new RuntimeException("Token generation failed", e);
        }
    }
}
