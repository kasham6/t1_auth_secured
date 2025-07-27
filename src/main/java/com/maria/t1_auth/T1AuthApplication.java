package com.maria.t1_auth;

import com.maria.t1_auth.config.JwtConfig;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;

@SpringBootApplication
public class T1AuthApplication {

    public static void main(String[] args) {
        SpringApplication.run(T1AuthApplication.class, args);
    }

}
