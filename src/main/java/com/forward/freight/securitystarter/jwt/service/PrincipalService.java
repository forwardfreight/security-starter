package com.forward.freight.securitystarter.jwt.service;

import com.forward.freight.securitystarter.jwt.UserAuthenticationToken;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class PrincipalService {

    public String getCurrentUserName() {
         var authentication = (UserAuthenticationToken) SecurityContextHolder.getContext().getAuthentication();
         return authentication.getUserName();
    }

    public String getCurrentUserEmail() {
        var authentication = (UserAuthenticationToken) SecurityContextHolder.getContext().getAuthentication();
        return authentication.getEmail();
    }

    public String getCurrentUserPhone() {
        var authentication = (UserAuthenticationToken) SecurityContextHolder.getContext().getAuthentication();
        return authentication.getPhoneNumber();
    }

    public String getCurrentToken() {
        var authentication = (UserAuthenticationToken) SecurityContextHolder.getContext().getAuthentication();
        return (String) authentication.getCredentials();
    }
}
