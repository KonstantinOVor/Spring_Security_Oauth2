package com.example.Spring_Security._Oauth2.repository;

import com.example.Spring_Security._Oauth2.model.Role;
import com.example.Spring_Security._Oauth2.model.RoleName;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface RoleRepository extends JpaRepository<Role, Long> {
    Optional<Role> findByName(RoleName name);
}