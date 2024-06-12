package com.forward.freight.securitystarter.jwt.controller;

import com.forward.freight.securitystarter.jwt.model.UserData;
import com.forward.freight.securitystarter.jwt.service.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@ConditionalOnProperty("user-api.enabled")
@RequestMapping("/user")
@RequiredArgsConstructor
public class UserController {
    private final UserService userService;

    @GetMapping
    public UserData getCurrentUser() {
        return userService.getUserData();
    }
}
