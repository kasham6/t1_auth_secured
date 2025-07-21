package com.maria.t1_auth.dto;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class RegistryRequest {
    private String username;
    private String email;
    private String password;
}
