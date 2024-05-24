package com.example.Spring_Security._Oauth2.controller;

import com.example.Spring_Security._Oauth2.dto.UserDTO;
import com.example.Spring_Security._Oauth2.service.impl.UserServiceImpl;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

@RestController
@RequestMapping("/api/v1")
@RequiredArgsConstructor
public class UserController {

    private final UserServiceImpl userService;

    @GetMapping()
    public ResponseEntity<UserDTO> profile() {
        UserDTO currentUser = userService.getCurrentUser();
        return ResponseEntity.ok(currentUser);
    }

    @GetMapping("/admin")
    public ResponseEntity<String> adminData() {
        return ResponseEntity.ok("Конфиденциальная информация администратора");
    }

    @GetMapping("/user")
    public ResponseEntity<String> userData() {
        return ResponseEntity.ok("Конфиденциальная информация пользователя");
    }

    @GetMapping("/logout")
    public ResponseEntity<String> logout(HttpServletRequest request, HttpServletResponse response) {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth != null) {
            SecurityContextLogoutHandler logoutHandler = new SecurityContextLogoutHandler();
            logoutHandler.logout(request, response, auth);
            return ResponseEntity.ok("Вы вышли из системы");
        } else {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Ошибка выхода: пользователь не аутентифицирован");
        }
    }
}