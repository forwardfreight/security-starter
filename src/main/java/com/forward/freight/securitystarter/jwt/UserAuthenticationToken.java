package com.forward.freight.securitystarter.jwt;

import lombok.Builder;
import lombok.Getter;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;

import java.util.Collection;
import java.util.List;

@Getter
public class UserAuthenticationToken extends UsernamePasswordAuthenticationToken {

    private final String username;
    private final String name;
    private final String familyName;
    private final String phoneNumber;
    private final String email;


    @Builder
    public UserAuthenticationToken(Object principal, Object credentials,
                                   Collection<? extends GrantedAuthority> authorities,
                                   String username, String name, String familyName, String email, String phoneNumber) {
        super(principal, credentials, authorities);
        this.username = username;
        this.name = name;
        this.familyName = familyName;
        this.email = email;
        this.phoneNumber = phoneNumber;
    }

}
