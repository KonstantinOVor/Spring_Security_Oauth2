package com.example.Spring_Security._Oauth2.aop;

import lombok.extern.slf4j.Slf4j;
import org.aspectj.lang.annotation.*;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;

@Aspect
@Component
@Slf4j
public class UserActionLoggerAspect {

    @Pointcut("execution(* com.example.Spring_Security._Oauth2.controller.UserController.profile(..))")
    public void profileAccessPointcut() {}

    @Pointcut("execution(* com.example.Spring_Security._Oauth2.controller.UserController.logout(..))")
    public void logoutPointcut() {}

    @Pointcut("execution(* com.example.Spring_Security._Oauth2.service.impl.UserServiceImpl.initRoles(..))")
    public void initRolesPointcut() {}

    @Pointcut("execution(* com.example.Spring_Security._Oauth2.service.impl.UserServiceImpl.initializeUsers(..))")
    public void initializeUsersPointcut() {}


    @Before("profileAccessPointcut()")
    public void logBeforeProfileAccess() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        log.info("Пользователь " + (auth != null ? auth.getName() : "анонимный") + " зашел в профиль.");
    }

    @After("logoutPointcut()")
    public void logAfterLogout() {
        log.info("Пользователь вышел из профиля.");
    }

    @Before("initRolesPointcut()")
    public void logBeforeInitRoles() {
        log.info("Инициализация ролей начинается.");
    }

    @After("initRolesPointcut()")
    public void logAfterInitRoles() {
        log.info("Инициализация ролей завершена.");
    }

    @Before("initializeUsersPointcut()")
    public void logBeforeInitializeUsers() {
        log.info("Инициализация пользователей и ролей начинается.");
    }

    @After("initializeUsersPointcut()")
    public void logAfterInitializeUsers() {
        log.info("Инициализация пользователей и ролей завершена.");
    }
}