package com.forward.freight.securitystarter.jwt.filter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import jakarta.servlet.Filter;
import java.io.IOException;

@Slf4j
@Component
@RequiredArgsConstructor
public class AwsCognitoJwtAuthenticationFilter implements Filter {

    private final AwsCognitoIdTokenProvider awsCognitoIdTokenProvider;

    @Override
    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain) throws IOException, ServletException {
        Authentication authentication = null;
        try {
            authentication = awsCognitoIdTokenProvider.getAuthentication((HttpServletRequest) servletRequest);

            if (authentication!=null) {
                SecurityContextHolder.getContext().setAuthentication(authentication);
            }

        } catch (Exception e) {
            log.error("Error occurred while processing Cognito ID Token",e);
            SecurityContextHolder.clearContext();
        }

        filterChain.doFilter(servletRequest, servletResponse);
    }

}
