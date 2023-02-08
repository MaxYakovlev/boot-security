package com.bootsecurity.controller;

import com.bootsecurity.domain.dto.LoginDto;
import com.bootsecurity.domain.dto.RegisterDto;
import com.bootsecurity.domain.entity.AppUser;
import com.bootsecurity.domain.enums.Role;
import com.bootsecurity.repository.AppUserRepository;
import com.bootsecurity.service.jwt.JwtService;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Optional;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthenticationController {
    private final AppUserRepository appUserRepository;
    private final PasswordEncoder passwordEncoder;
    private final AuthenticationManager authenticationManager;
    private final JwtService jwtService;

    @PostMapping("/register")
    public Map<String, Object> registerHandler(@RequestBody RegisterDto model){
        Optional<AppUser> foundAppUser = appUserRepository.findByEmail(model.getEmail());
        if (foundAppUser.isPresent()) {
            return Collections.singletonMap("error", "email already registered");
        }
        String encodedPassword = passwordEncoder.encode(model.getPassword());

        AppUser appUser = new AppUser();
        appUser.setPassword(encodedPassword);
        appUser.setEmail(model.getEmail());
        appUser.setRole(Role.ROLE_USER);

        appUserRepository.save(appUser);

        UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(model.getEmail(), model.getPassword(), List.of(new SimpleGrantedAuthority(appUser.getRole().name())));
        authenticationManager.authenticate(authToken);

        String token = jwtService.generateToken(appUser.getEmail(), Role.ROLE_USER.name());

        return Collections.singletonMap("jwt-token", token);
    }

    @PostMapping("/login")
    public Map<String, Object> loginHandler(@RequestBody LoginDto model){
        Optional<AppUser> foundAppUser = appUserRepository.findByEmail(model.getEmail());
        if (foundAppUser.isEmpty()) {
            return Collections.singletonMap("error", "user not found");
        }
        AppUser appUser = foundAppUser.get();
        if (!passwordEncoder.matches(model.getPassword(), appUser.getPassword())) {
            return Collections.singletonMap("error", "invalid password");
        }
        UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(model.getEmail(), model.getPassword(), List.of(new SimpleGrantedAuthority(appUser.getRole().name())));
        authenticationManager.authenticate(authToken);

        String token = jwtService.generateToken(appUser.getEmail(), Role.ROLE_USER.name());

        return Collections.singletonMap("jwt-token", token);
    }
}
