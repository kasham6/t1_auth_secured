package com.maria.t1_auth;

import com.maria.t1_auth.dto.AuthResponse;
import com.maria.t1_auth.dto.LoginRequest;
import com.maria.t1_auth.dto.RegistryRequest;
import com.maria.t1_auth.model.Role;
import com.maria.t1_auth.model.User;
import com.maria.t1_auth.repository.UserRepository;
import com.maria.t1_auth.service.AuthService;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jose.JOSEException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.ValueOperations;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.time.Duration;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class AuthServiceTest {

    private UserRepository userRepository;
    private com.maria.t1_auth.service.JwtService jwtService;
    private StringRedisTemplate redis;
    private ValueOperations<String, String> valueOps;
    private PasswordEncoder passwordEncoder;
    private AuthService authService;

    @BeforeEach
    void setUp() {
        userRepository   = mock(UserRepository.class);
        jwtService       = mock(com.maria.t1_auth.service.JwtService.class);
        redis            = mock(StringRedisTemplate.class);
        valueOps         = mock(ValueOperations.class);
        passwordEncoder  = mock(PasswordEncoder.class);

        when(redis.opsForValue()).thenReturn(valueOps);
        authService = new AuthService(userRepository, jwtService, redis, passwordEncoder);
    }

    @Test
    void signUp_shouldRegisterNewUser_andStoreRefreshJti() throws Exception {
        RegistryRequest req = new RegistryRequest();
        req.setUsername("marus");
        req.setEmail("marus@live.com");
        req.setPassword("pass");

        when(userRepository.existsByUsername("marus")).thenReturn(false);
        when(userRepository.existsByEmail("marus@live.com")).thenReturn(false);
        when(passwordEncoder.encode("pass")).thenReturn("hashed-pass");

        doAnswer(inv -> {
            User u = inv.getArgument(0);
            u.setId(1L);
            return u;
        }).when(userRepository).save(any(User.class));

        when(jwtService.generateAccessToken(any())).thenReturn("access-token");
        when(jwtService.generateRefreshToken(any())).thenReturn("refresh-token");
        when(jwtService.parseRefreshToken("refresh-token"))
                .thenReturn(new JWTClaimsSet.Builder().jwtID("jti-1").build());

        AuthResponse resp = authService.signUp(req);

        assertEquals("access-token", resp.getAccessToken());
        assertEquals("refresh-token", resp.getRefreshToken());

        ArgumentCaptor<User> userCap = ArgumentCaptor.forClass(User.class);
        verify(userRepository).save(userCap.capture());
        User saved = userCap.getValue();
        assertEquals("marus", saved.getUsername());
        assertEquals(Set.of(Role.GUEST), saved.getRoles());

        verify(valueOps)
                .set(eq("refresh:jti-1"), eq("1"), eq(Duration.ofDays(7)));
    }

    @Test
    void logIn_shouldReturnTokens() throws Exception {
        LoginRequest req = new LoginRequest();
        req.setUsername("marus");
        req.setPassword("pass");

        User user = new User();
        user.setUsername("marus");
        user.setPasswordHash("hashed");

        when(userRepository.getUserByUsername("marus")).thenReturn(user);
        when(passwordEncoder.matches("pass", "hashed")).thenReturn(true);
        when(jwtService.generateAccessToken(user)).thenReturn("access");
        when(jwtService.generateRefreshToken(user)).thenReturn("refresh");
        when(jwtService.parseRefreshToken("refresh"))
                .thenReturn(new JWTClaimsSet.Builder().jwtID("jti-login").build());

        AuthResponse resp = authService.logIn(req);

        assertEquals("access", resp.getAccessToken());
        assertEquals("refresh", resp.getRefreshToken());
        verify(valueOps)
                .set(eq("refresh:jti-login"), anyString(), eq(Duration.ofDays(7)));
    }

    @Test
    void refreshAccessToken_shouldRotateTokens_andStoreNewJti() throws Exception {
        String oldToken = "old-refresh";

        when(jwtService.parseRefreshToken(oldToken))
                .thenReturn(new JWTClaimsSet.Builder().jwtID("old-jti").build());

        when(valueOps.get("refresh:old-jti")).thenReturn("1");
        User user = new User(); user.setId(1L); user.setUsername("marus");
        when(userRepository.findById(1L)).thenReturn(Optional.of(user));

        when(jwtService.generateAccessToken(user)).thenReturn("new-access");
        when(jwtService.generateRefreshToken(user)).thenReturn("new-refresh");
        when(jwtService.parseRefreshToken("new-refresh"))
                .thenReturn(new JWTClaimsSet.Builder().jwtID("new-jti").build());

        AuthResponse resp = authService.refreshAccessToken(oldToken);

        assertEquals("new-access", resp.getAccessToken());
        assertEquals("new-refresh", resp.getRefreshToken());

        verify(redis).delete("refresh:old-jti");
        verify(valueOps)
                .set(eq("refresh:new-jti"), eq("1"), eq(Duration.ofDays(7)));
    }

    @Test
    void logout_shouldDeleteRefreshJti() throws Exception {
        String token = "some-refresh";
        when(jwtService.parseRefreshToken(token))
                .thenReturn(new JWTClaimsSet.Builder().jwtID("logout-jti").build());
        authService.logout(token);

        verify(redis).delete("refresh:logout-jti");
    }
}
