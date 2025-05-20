package com.developer.account.user.config;

import com.developer.account.user.service.JWTService;
import com.developer.account.user.model.User;
import com.developer.account.user.repository.UserRepository;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Collections;
import java.util.Optional;

@Component
public class JWTRequestFilter extends OncePerRequestFilter {

    private static final Logger logger = LoggerFactory.getLogger(JWTRequestFilter.class);

    private final JWTService jwtService;
    private final UserRepository userRepository;

    public JWTRequestFilter(JWTService jwtService, UserRepository userRepository) {
        this.jwtService = jwtService;
        this.userRepository = userRepository;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain chain) throws ServletException, IOException {
        final String authHeader = request.getHeader("Authorization");

        String token = null;
        String email = null;

        // Extract token
        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            token = authHeader.substring(7);
            try {
                if (!jwtService.isTokenInvalidated(token)) {
                    email = jwtService.getEmail(token);
                } else {
                    logger.warn("Token is invalidated: {}", token);
                }
            } catch (Exception e) {
                logger.error("Invalid JWT token: {}", e.getMessage());
            }
        }

        // Authenticate
        if (email != null && SecurityContextHolder.getContext().getAuthentication() == null) {
            Optional<User> userOptional = userRepository.findByEmail(email);
            if (userOptional.isPresent()) {
                User user = userOptional.get();

                UsernamePasswordAuthenticationToken authentication =
                        new UsernamePasswordAuthenticationToken(user, null, Collections.emptyList());

                authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

                SecurityContextHolder.getContext().setAuthentication(authentication);
                logger.info("Authenticated user: {}", user.getEmail());
            } else {
                logger.warn("User not found for email extracted from JWT: {}", email);
            }
        }

        chain.doFilter(request, response);
    }
}
