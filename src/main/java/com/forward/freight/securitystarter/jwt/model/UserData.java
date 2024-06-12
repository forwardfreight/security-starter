package com.forward.freight.securitystarter.jwt.model;

import lombok.Builder;
import lombok.Data;

import java.util.List;

@Data
@Builder
public class UserData {
    private String fullName;
    private String name;
    private String familyName;
    private String username;
    private String email;
    private String telephone;
    private List<String> roles;
}
