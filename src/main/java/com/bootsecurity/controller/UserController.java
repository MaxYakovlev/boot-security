package com.bootsecurity.controller;

import com.bootsecurity.domain.entity.AppUser;
import com.bootsecurity.repository.AppUserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.security.Principal;

@RestController
@RequestMapping("/api/user")
@RequiredArgsConstructor
public class UserController {
    private final AppUserRepository appUserRepository;

    @GetMapping("/info")
    public AppUser getUserDetails(Principal principal){
        String email = principal.getName();
        return appUserRepository
                .findByEmail(email)
                .orElseThrow(() -> new UsernameNotFoundException("Could not findUser with email: " + email));
    }
}
