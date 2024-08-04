package com.forward.freight.securitystarter.jwt.filter;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.forward.freight.securitystarter.jwt.UserAuthenticationToken;
import com.forward.freight.securitystarter.jwt.config.JwtConfiguration;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.jwt.proc.ConfigurableJWTProcessor;
import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.stereotype.Component;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Optional;
import java.util.Spliterator;
import java.util.Spliterators;
import java.util.stream.Collectors;
import java.util.stream.StreamSupport;


@Slf4j
@Component
public class AwsCognitoIdTokenProvider {

    @Autowired
    private JwtConfiguration jwtConfiguration;

    @Autowired
    private ConfigurableJWTProcessor configurableJWTProcessor;

    public Authentication getAuthentication(HttpServletRequest request) throws Exception {

        var token = request.getHeader(jwtConfiguration.getHttpHeader());
        var signedJwt = SignedJWT.parse(token);

       List<String> headerNames = StreamSupport.stream(Spliterators.spliteratorUnknownSize(
            request.getHeaderNames().asIterator(), Spliterator.ORDERED), false)
            .toList();

       headerNames.forEach(name -> {
           log.info("HEADER " + name + " = " + request.getHeader(name));
       });


        if(signedJwt != null) {
            var claims = signedJwt.getJWTClaimsSet();

            log.info("x-amzn-oidc-data = ", request.getHeader("x-amzn-oidc-data"));
            log.info("x-amzn-oidc-identity = ", request.getHeader("x-amzn-oidc-identity"));
            log.info("CLAIMS = " + claims.getClaims().toString());
            var username = (String) claims.getClaim("username");
            var principal = new User(username, "", Collections.emptyList());

            return UserAuthenticationToken.builder()
                .principal(principal)
                .credentials(token)
                .username(username)
                .name((String) claims.getClaim("name"))
                .familyName((String) claims.getClaim("family_name"))
                .email((String) claims.getClaim("email"))
                .phoneNumber((String) claims.getClaim("phone_number"))
                .authorities(getAuthorities(claims))
                .build();
        }
        log.info("No idToken found in HTTP Header");
        return null;
    }

    private List<GrantedAuthority> getAuthorities(JWTClaimsSet claims) {
        return Optional.of((String) claims.getClaim("custom:roles"))
            .map(roles -> Arrays.stream(roles.split(",")).collect(Collectors.toList()))
            .orElse(Collections.emptyList())
            .stream()
            .map(group -> new SimpleGrantedAuthority("ROLE_" + group.toUpperCase()))
            .collect(Collectors.toList());
    }

}
