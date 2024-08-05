package com.forward.freight.securitystarter.jwt.filter;

import com.forward.freight.securitystarter.jwt.UserAuthenticationToken;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
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

    public Authentication getAuthentication(HttpServletRequest request) throws Exception {
        var token = request.getHeader("x-amzn-oidc-data");

       List<String> headerNames = StreamSupport.stream(Spliterators.spliteratorUnknownSize(
            request.getHeaderNames().asIterator(), Spliterator.ORDERED), false)
            .toList();

       headerNames.forEach(name -> {
           log.info("HEADER " + name + " = " + request.getHeader(name));
       });

        if(StringUtils.isNotBlank(token)) {
            var signedJwt = SignedJWT.parse(token);
            var claims = signedJwt.getJWTClaimsSet();

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
