package com.bootsecurity.service.jwt;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTCreationException;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.Collections;
import java.util.Date;
import java.util.List;

@Service
public class JwtService {
    @Value("${jwt.secret}")
    private String secret;

    public String generateToken(String email, String role) throws IllegalArgumentException, JWTCreationException {
        return JWT
                .create()
                .withSubject("User Details")
                .withClaim("email", email)
                .withClaim("role", role)
                .withIssuedAt(new Date())
                .withExpiresAt(Instant.now().plusSeconds(60 * 60 * 24 * 30))
                .withIssuer("boot-security")
                .sign(Algorithm.HMAC256(secret));
    }

    public DecodedJWT validateToken(String token) throws JWTVerificationException {
        JWTVerifier verifier = JWT
                .require(Algorithm.HMAC256(secret))
                .withSubject("User Details")
                .withIssuer("boot-security")
                .build();
        return verifier.verify(token);
    }

    public String retrieveEmail(DecodedJWT jwt) {
        return jwt
                .getClaim("email")
                .asString();
    }

    public List<SimpleGrantedAuthority> retrieveGrantedAuthorities(DecodedJWT jwt) {
        return Collections.singletonList(
                new SimpleGrantedAuthority(
                        jwt
                            .getClaim("role")
                            .asString()
                )
        );
    }
}
