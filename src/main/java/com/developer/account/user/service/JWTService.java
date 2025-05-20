package com.developer.account.user.service;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.developer.account.user.model.User;
import jakarta.annotation.PostConstruct;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.util.Date;
import java.util.HashSet;
import java.util.Set;

@Service
public class JWTService {

    @Value("${jwt.algorithm.key}")
    private String algorithmKey;

    @Value("${jwt.issuer}")
    private String issuer;

    @Value("${jwt.expiryInSeconds}")
    private int expiryInSeconds;

    private Algorithm algorithm;

    private static final String EMAIL_KEY = "EMAIL";
    private static final String RESET_PASSWORD_EMAIL_KEY = "RESET_PASSWORD_EMAIL";

    private final Set<String> invalidatedTokens = new HashSet<>();

    @PostConstruct
    public void postConstruct() {
        this.algorithm = Algorithm.HMAC256(algorithmKey);
    }

    // Normal login token
    public String generateJWT(User user) {
        return JWT.create()
                .withClaim(EMAIL_KEY, user.getEmail())
                .withExpiresAt(new Date(System.currentTimeMillis() + (1000L * expiryInSeconds)))
                .withIssuer(issuer)
                .sign(algorithm);
    }

    // 6-digit password reset code
    public String generatePasswordResetToken(User user) {
        int code = 100000 + (int) (Math.random() * 900000); // generates number from 100000 to 999999
        return String.valueOf(code);
    }


    // Extract email from reset token
    public String getResetPasswordEmail(String token) {
        DecodedJWT jwt = JWT.require(algorithm)
                .withIssuer(issuer)
                .build()
                .verify(token);

        String email = jwt.getClaim(RESET_PASSWORD_EMAIL_KEY).asString();
        if (email == null || email.isEmpty()) {
            throw new IllegalArgumentException("Invalid token: no email found");
        }
        return email;
    }

    // Extract email from login token
    public String getEmail(String token) {
        DecodedJWT jwt = JWT.require(algorithm)
                .withIssuer(issuer)
                .build()
                .verify(token);
        return jwt.getClaim(EMAIL_KEY).asString();
    }

    // Token invalidation for logout/blacklisting
    public void invalidateToken(String token) {
        invalidatedTokens.add(token);
    }

    public boolean isTokenInvalidated(String token) {
        return invalidatedTokens.contains(token);
    }
}
