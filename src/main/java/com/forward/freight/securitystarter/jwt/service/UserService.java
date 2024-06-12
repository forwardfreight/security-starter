package com.forward.freight.securitystarter.jwt.service;

import com.forward.freight.securitystarter.jwt.UserAuthenticationToken;
import com.forward.freight.securitystarter.jwt.model.UserData;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;

@Service
@ConditionalOnProperty("user-api.enabled")
public class UserService {

    public UserData getUserData() {
            var authentication = (UserAuthenticationToken) SecurityContextHolder.getContext().getAuthentication();
            return UserData.builder()
                .fullName(authentication.getName() + " " + authentication.getFamilyName())
                .name(authentication.getName())
                .familyName(authentication.getFamilyName())
                .username(authentication.getUsername())
                .email(authentication.getEmail())
                .telephone(authentication.getPhoneNumber())
                .roles(authentication.getAuthorities().stream().map(GrantedAuthority::getAuthority).toList())
                .build();
    }
}
