package com.forward.freight.securitystarter.jwt;

import com.forward.freight.securitystarter.jwt.filter.AwsCognitoJwtAuthenticationFilter;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;

@Order(SecurityConfig.DEFAULT_ORDER)
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {
    public static final int DEFAULT_ORDER = Ordered.HIGHEST_PRECEDENCE + 10;
    public static final String[] ENDPOINTS_WHITELIST = {
        "/actuator/**",
        "/swagger-doc/**"
    };

    private final AwsCognitoJwtAuthenticationFilter awsCognitoJwtAuthenticationFilter;

    @Bean
    public SecurityFilterChain securityWebFilterChain(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests(authorize -> authorize.requestMatchers(ENDPOINTS_WHITELIST).permitAll());
        http.authorizeHttpRequests(authorize -> authorize
                .anyRequest().authenticated());
        http.addFilterBefore(awsCognitoJwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class);
        http.csrf(AbstractHttpConfigurer::disable);
        return http.build();
    }
}
