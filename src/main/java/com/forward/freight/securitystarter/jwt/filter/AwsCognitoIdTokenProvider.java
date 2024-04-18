package com.forward.freight.securitystarter.jwt.filter;

import com.forward.freight.securitystarter.jwt.UserAuthenticationToken;
import com.forward.freight.securitystarter.jwt.config.JwtConfiguration;
import com.nimbusds.jwt.proc.ConfigurableJWTProcessor;
import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.User;
import org.springframework.stereotype.Component;

import java.util.Collections;


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
            var userName = (String) claims.getClaim("cognito:username");
            var principal = new User(userName, "", Collections.emptyList());

            return UserAuthenticationToken.builder()
                .principal(principal)
                .credentials(idToken)
                .userName(userName)
                .email((String) claims.getClaim("email"))
                .phoneNumber((String) claims.getClaim("phone_number"))
                .build();
        }
        log.trace("No idToken found in HTTP Header");
        return null;
    }


}
