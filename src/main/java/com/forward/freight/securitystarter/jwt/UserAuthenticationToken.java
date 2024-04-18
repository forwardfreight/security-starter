package com.forward.freight.securitystarter.jwt;

import lombok.Builder;
import lombok.Getter;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;

import java.util.Collection;

@Getter
public class UserAuthenticationToken extends UsernamePasswordAuthenticationToken {

    private final String userName;
    private final String phoneNumber;
    private final String email;


    @Builder
    public UserAuthenticationToken(Object principal, Object credentials,
                                   Collection<? extends GrantedAuthority> authorities,
                                   String userName, String email, String phoneNumber) {
        super(principal, credentials, authorities);
        this.userName = userName;
        this.email = email;
        this.phoneNumber = phoneNumber;
    }

}
