package com.forward.freight.securitystarter.jwt.config;

import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.jwk.source.RemoteJWKSet;
import com.nimbusds.jose.proc.JWSKeySelector;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.util.DefaultResourceRetriever;
import com.nimbusds.jose.util.ResourceRetriever;
import com.nimbusds.jwt.proc.ConfigurableJWTProcessor;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.net.MalformedURLException;
import java.net.URL;

import static com.nimbusds.jose.JWSAlgorithm.RS256;

@Data
@Configuration
@ConfigurationProperties(prefix = "com.security.jwt.aws")
public class JwtConfiguration {
    private static final String COGNITO_IDENTITY_POOL_URL = "https://cognito-idp.%s.amazonaws.com/%s";
    private static final String JSON_WEB_TOKEN_SET_URL_SUFFIX = "/.well-known/jwks.json";

    private String userNameField = "cognito:username";
    private String region = "us-east-1";
    private String userPoolId;
    private String groupsField = "cognito:groups";
    private int connectionTimeout = 2000;
    private int readTimeout = 2000;
    private String httpHeader = "x-amzn-oidc-accestoken";
    private String jwkUrl;


    @Bean
    public ConfigurableJWTProcessor configurableJWTProcessor() throws MalformedURLException {
        ResourceRetriever resourceRetriever = new DefaultResourceRetriever(connectionTimeout, readTimeout);
        URL jwkSetURL = new URL(getJwkUrl());
        JWKSource keySource = new RemoteJWKSet(jwkSetURL, resourceRetriever);
        ConfigurableJWTProcessor jwtProcessor = new DefaultJWTProcessor();
        JWSKeySelector keySelector = new JWSVerificationKeySelector(RS256, keySource);
        jwtProcessor.setJWSKeySelector(keySelector);
        return jwtProcessor;
    }

    private String getJwkUrl() {
        if (jwkUrl==null || jwkUrl.isEmpty()) {
            return String.format(COGNITO_IDENTITY_POOL_URL + JSON_WEB_TOKEN_SET_URL_SUFFIX, region, userPoolId);
        }
        return jwkUrl;
    }
}
