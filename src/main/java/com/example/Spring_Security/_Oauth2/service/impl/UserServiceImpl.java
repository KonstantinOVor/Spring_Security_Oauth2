package com.example.Spring_Security._Oauth2.service.impl;

import com.example.Spring_Security._Oauth2.dto.UserDTO;
import com.example.Spring_Security._Oauth2.model.Role;
import com.example.Spring_Security._Oauth2.model.RoleName;
import com.example.Spring_Security._Oauth2.model.User;
import com.example.Spring_Security._Oauth2.repository.RoleRepository;
import com.example.Spring_Security._Oauth2.repository.UserRepository;
import com.example.Spring_Security._Oauth2.service.UserService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.stereotype.Service;
import javax.annotation.PostConstruct;
import java.util.Collections;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
@Slf4j
public class UserServiceImpl implements UserDetailsService, UserService {

    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final PasswordEncoder passwordEncoder;

    @PostConstruct
    public void initializeUsers() {
        if (roleRepository.findByName(RoleName.USER).isEmpty()) {
            roleRepository.save(new Role(RoleName.USER));
        }
        if (roleRepository.findByName(RoleName.ADMIN).isEmpty()) {
            roleRepository.save(new Role(RoleName.ADMIN));
        }
        Role adminRole = roleRepository.findByName(RoleName.ADMIN)
                .orElseThrow(() -> new RuntimeException("Роль ADMIN не найдена"));
        Role userRole = roleRepository.findByName(RoleName.USER)
                .orElseThrow(() -> new RuntimeException("Роль USER не найдена"));

        createUserIfNotExist("admin", "admin@example.com", "admin",
                new HashSet<>(Set.of(adminRole, userRole)));
        createUserIfNotExist("user", "user@example.com", "user", Collections.singleton(userRole));
    }

    private void createUserIfNotExist(String username, String email, String password, Set<Role> roles) {
        if (userRepository.findByUsername(username).isEmpty()) {
            User user = User.builder()
                    .username(username)
                    .password(passwordEncoder.encode(password))
                    .email(email)
                    .roles(roles)
                    .build();
            userRepository.save(user);
        }
    }
    @Override
    public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
        return userRepository.findByEmail(email)
                .map(user -> new org.springframework.security.core.userdetails.User(
                        user.getUsername(),
                        user.getPassword(),
                        user.getRoles().stream()
                                .map(role -> new SimpleGrantedAuthority(role.getName().name()))
                                .collect(Collectors.toList())
                ))
                .orElseThrow(() -> new UsernameNotFoundException("Пользователь не найден: " + email));
    }

    @Override
    public UserDTO getCurrentUser() {
        OidcUser oidcUser = (OidcUser) SecurityContextHolder.getContext().getAuthentication().getPrincipal();

        Map<String, Object> attributes = oidcUser.getAttributes();
        String userEmail = (String) attributes.get("email");

        User user = userRepository.findByEmail(userEmail)
                .orElseThrow(() -> new UsernameNotFoundException("Пользователь не найден: " + userEmail));

        return UserDTO.builder()
                .username(user.getUsername())
                .email(user.getEmail())
                .build();
    }
}

