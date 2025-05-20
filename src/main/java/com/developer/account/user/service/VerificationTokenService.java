package com.developer.account.user.service;

import com.developer.account.user.model.User;
import com.developer.account.user.model.VerificationToken;
import com.developer.account.user.repository.VerificationTokenRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.Optional;
import java.util.UUID;

@Service
public class VerificationTokenService {
    @Autowired
    private VerificationTokenRepository repository;

    public VerificationToken createToken(User user, int hoursValid) {
        VerificationToken token = new VerificationToken();
        token.setUser(user);
        token.setToken(UUID.randomUUID().toString());
        token.generateTimestamps(hoursValid);
        return repository.save(token);
    }

    public Optional<VerificationToken> findByToken(String token) {
        return repository.findByToken(token);
    }

    public void deleteByUser(User user) {
        repository.deleteByUser(user);
    }
}
