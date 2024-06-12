package com.forward.freight.securitystarter.jwt.filter;

import com.forward.freight.securitystarter.jwt.UserAuthenticationToken;
import com.forward.freight.securitystarter.jwt.config.JwtConfiguration;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.proc.ConfigurableJWTProcessor;
import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.stereotype.Component;

import java.util.Collections;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;


@Slf4j
@Component
public class AwsCognitoIdTokenProvider {

    @Autowired
    private JwtConfiguration jwtConfiguration;

    @Autowired
    private ConfigurableJWTProcessor configurableJWTProcessor;

    public Authentication getAuthentication(HttpServletRequest request) throws Exception {
        var idToken = request.getHeader(jwtConfiguration.getHttpHeader());
        if(idToken != null) {
            var claims = configurableJWTProcessor.process(idToken, null);
            var username = (String) claims.getClaim("cognito:username");
            var principal = new User(username, "", Collections.emptyList());

            return UserAuthenticationToken.builder()
                .principal(principal)
                .credentials(idToken)
                .username(username)
                .name((String) claims.getClaim("name"))
                .familyName((String) claims.getClaim("family_name"))
                .email((String) claims.getClaim("email"))
                .phoneNumber((String) claims.getClaim("phone_number"))
                .authorities(getAuthorities(claims))
                .build();
        }
        log.trace("No idToken found in HTTP Header");
        return null;
    }

    private List<GrantedAuthority> getAuthorities(JWTClaimsSet claims) {
        return Optional.of((List<String>) claims.getClaim("cognito:groups"))
            .orElse(Collections.emptyList())
            .stream()
            .map(group -> new SimpleGrantedAuthority("ROLE_" + group.toUpperCase()))
            .collect(Collectors.toList());
    }


}
