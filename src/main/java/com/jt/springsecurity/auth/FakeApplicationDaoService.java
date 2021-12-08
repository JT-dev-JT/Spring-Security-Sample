package com.jt.springsecurity.auth;

import com.google.common.collect.Lists;
import com.jt.springsecurity.student.Student;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

import static com.jt.springsecurity.security.ApplicationUserRole.*;
@Repository("fake")
public class FakeApplicationDaoService implements ApplicationUserDao{

    private final PasswordEncoder passwordEncoder;

    @Autowired
    public FakeApplicationDaoService(PasswordEncoder passwordEncoder) {
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    public Optional<ApplicationUser> selectApplicationUserByUserName(String username) {
        return getApplicationUsers().stream()
                .filter(applicationUser -> username.equals(applicationUser.getUsername()))
                .findFirst();
    }

    private List<ApplicationUser> getApplicationUsers(){
        List<ApplicationUser> applicationUsers= Lists.newArrayList(
                new ApplicationUser(
                        "annasmith",
                        passwordEncoder.encode("pass"),
                        STUDENT.getGrantedAuthorities(),
                        true,
                        true,
                        true,
                        true

                ),
                new ApplicationUser(
                        "linda",
                        passwordEncoder.encode("pass"),
                        ADMIN.getGrantedAuthorities(),
                        true,
                        true,
                        true,
                        true

                ),
                new ApplicationUser(
                        "tom",
                        passwordEncoder.encode("pass"),
                        ADMINTRAINEE.getGrantedAuthorities(),
                        true,
                        true,
                        true,
                        true

                )
        );

        return applicationUsers;
    }
}
