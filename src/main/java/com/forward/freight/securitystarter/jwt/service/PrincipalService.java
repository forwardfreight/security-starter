package com.forward.freight.securitystarter.jwt.service;

import com.forward.freight.securitystarter.jwt.UserAuthenticationToken;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class PrincipalService {

    public UserAuthenticationToken getCurrentUser() {
         return (UserAuthenticationToken) SecurityContextHolder.getContext().getAuthentication();
    }

}
