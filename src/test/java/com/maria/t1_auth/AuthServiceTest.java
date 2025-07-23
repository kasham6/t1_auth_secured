package com.maria.t1_auth;


import com.maria.t1_auth.dto.AuthResponse;
import com.maria.t1_auth.dto.LoginRequest;
import com.maria.t1_auth.dto.RegistryRequest;
import com.maria.t1_auth.model.Role;
import com.maria.t1_auth.model.User;
import com.maria.t1_auth.repository.UserRepository;
import com.maria.t1_auth.service.AuthService;
import com.maria.t1_auth.service.JwtService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.ValueOperations;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.Optional;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class AuthServiceTest {

    private UserRepository userRepository;
    private JwtService jwtService;
    private StringRedisTemplate redis;
    private ValueOperations<String, String> valueOps;
    private PasswordEncoder passwordEncoder;
    private AuthService authService;

    @BeforeEach
    void setUp() {
        userRepository = mock(UserRepository.class);
        jwtService = mock(JwtService.class);
        redis = mock(StringRedisTemplate.class);
        valueOps = mock(ValueOperations.class);
        passwordEncoder = mock(PasswordEncoder.class);
        when(redis.opsForValue()).thenReturn(valueOps);
        authService = new AuthService(userRepository, jwtService, redis, passwordEncoder);
    }

    @Test
    void signUp_shouldRegisterNewUser() {
        RegistryRequest request = new RegistryRequest();
        request.setUsername("marus");
        request.setEmail("marus@live.com");
        request.setPassword("pass");

        when(userRepository.existsByUsername("marus")).thenReturn(false);
        when(userRepository.existsByEmail("marus@live.com")).thenReturn(false);
        when(passwordEncoder.encode("pass")).thenReturn("hashed-pass");
        when(jwtService.generateAccessToken(any())).thenReturn("access-token");
        when(jwtService.generateRefreshToken(any())).thenReturn("refresh-token");

        AuthResponse response = authService.signUp(request);

        assertEquals("access-token", response.getAccessToken());
        assertNotNull(response.getRefreshToken());
        assertFalse(response.getRefreshToken().isEmpty());

        ArgumentCaptor<User> captor = ArgumentCaptor.forClass(User.class);
        verify(userRepository).save(captor.capture());
        assertEquals("marus", captor.getValue().getUsername());
        assertEquals(Set.of(Role.GUEST), captor.getValue().getRoles());
    }

    @Test
    void logIn_shouldReturnTokens() {
        LoginRequest request = new LoginRequest();
        request.setUsername("marus");
        request.setPassword("pass");

        User user = new User();
        user.setUsername("marus");
        user.setPasswordHash("hashed");

        when(userRepository.getUserByUsername("marus")).thenReturn(user);
        when(passwordEncoder.matches("pass", "hashed")).thenReturn(true);
        when(jwtService.generateAccessToken(user)).thenReturn("access");
        when(jwtService.generateRefreshToken(user)).thenReturn("refresh");

        AuthResponse response = authService.logIn(request);

        assertEquals("access", response.getAccessToken());
        assertNotNull(response.getRefreshToken());
        assertFalse(response.getRefreshToken().isEmpty());
    }

    @Test
    void refreshAccessToken_shouldReturnNewAccessToken() {
        User user = new User();
        user.setId(1L);
        user.setUsername("marus");

        when(redis.opsForValue().get("refresh:token")).thenReturn("1");
        when(userRepository.findById(1L)).thenReturn(Optional.of(user));
        when(jwtService.generateAccessToken(user)).thenReturn("new-access");

        AuthResponse response = authService.refreshAccessToken("token");

        assertEquals("new-access", response.getAccessToken());
        assertEquals("token", response.getRefreshToken());
    }

    @Test
    void logout_shouldDeleteToken() {
        authService.logout("token");
        verify(redis).delete("refresh:token");
    }
}

