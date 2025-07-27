package com.maria.t1_auth.config;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

@Component
@ConfigurationProperties(prefix = "jwt")
@Getter
@Setter
public class JwtConfig {
    @Getter
    @Setter
    public static class KeyPair {
        private String privateKey;
        private String publicKey;
    }

    private KeyPair sign;
    private KeyPair enc;
    private long accessExp;
    private long refreshExp;
}