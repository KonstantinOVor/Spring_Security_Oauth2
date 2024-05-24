package com.example.Spring_Security._Oauth2.exception;

import org.springframework.http.HttpStatus;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.web.bind.annotation.ResponseStatus;

@ResponseStatus(HttpStatus.FORBIDDEN)
public class OAuth2AccessDeniedException extends RuntimeException {
    private final String requiredRole;

    public OAuth2AccessDeniedException(String requiredRole, AccessDeniedException accessDeniedException) {
        super("Доступ к ресурсу запрещен. Требуется роль: " + requiredRole);
        this.requiredRole = requiredRole;
    }

    public String getRequiredRole() {
        return requiredRole;
    }
}