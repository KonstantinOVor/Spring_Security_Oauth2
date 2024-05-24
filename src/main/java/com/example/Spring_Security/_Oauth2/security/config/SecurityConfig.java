package com.example.Spring_Security._Oauth2.security.config;

import com.example.Spring_Security._Oauth2.exception.OAuth2AccessDeniedException;
import com.example.Spring_Security._Oauth2.model.RoleName;
import com.example.Spring_Security._Oauth2.model.User;
import com.example.Spring_Security._Oauth2.repository.RoleRepository;
import com.example.Spring_Security._Oauth2.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.mapping.GrantedAuthoritiesMapper;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.user.OAuth2UserAuthority;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.access.AccessDeniedHandlerImpl;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
@RequiredArgsConstructor
public class SecurityConfig extends WebSecurityConfigurerAdapter {
    private final UserRepository userRepository;
    private final RoleRepository roleRepository;


    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .csrf().disable()
                .authorizeRequests()
                    .antMatchers("/login", "/logout").permitAll()
                    .antMatchers("/api/v1/admin/**").hasRole("ADMIN")
                    .anyRequest().authenticated()
                .and()
                    .exceptionHandling()
                    .accessDeniedHandler(accessDeniedHandler())
                .and()
                .oauth2Login(oauth2 -> oauth2
                        .userInfoEndpoint(userInfo -> userInfo
                                .userAuthoritiesMapper(userAuthoritiesMapper())
                        )
                )
                .logout(logout -> logout
                        .logoutUrl("/logout")
                        .logoutSuccessUrl("/login")
                        .invalidateHttpSession(true)
                        .deleteCookies("JSESSIONID"));
    }

    private GrantedAuthoritiesMapper userAuthoritiesMapper() {

        return authorities -> {
            Set<GrantedAuthority> grantedAuthorities = new HashSet<>();
            authorities.forEach(authority -> {
                if (authority instanceof OAuth2UserAuthority oAuth2UserAuthority) {
                    Map<String, Object> userAttributes = oAuth2UserAuthority.getAttributes();
                    String email = (String) userAttributes.get("email");
                    String name = (String) userAttributes.get("name");
                    String password =  String.valueOf(System.currentTimeMillis());
                    User user = userRepository.findByUsername(name).orElseGet(() -> {
                        User createUser = User.builder()
                                .username(name)
                                .email(email)
                                .password(password)
                                .roles(new HashSet<>())
                                .build();
                        createUser.getRoles().add(roleRepository.findByName(RoleName.USER).get());
                        userRepository.save(createUser);
                        return createUser;
                    });
                    grantedAuthorities.addAll(user.getRoles());
                }
            });
            return grantedAuthorities;
        };
    }

    @Bean
    public AccessDeniedHandler accessDeniedHandler() {
        return new AccessDeniedHandlerImpl() {
            @Override
            public void handle(HttpServletRequest request, HttpServletResponse response,
                               AccessDeniedException accessDeniedException){
                throw new OAuth2AccessDeniedException("ADMIN", accessDeniedException);
            }
        };
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}