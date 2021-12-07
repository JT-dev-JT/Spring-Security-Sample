package com.jt.springsecurity.auth;

import org.springframework.stereotype.Repository;

import java.util.Optional;
@Repository
public interface   ApplicationUserDao {
    public Optional<ApplicationUser> selectApplicationUserByUserName(String username);
}
