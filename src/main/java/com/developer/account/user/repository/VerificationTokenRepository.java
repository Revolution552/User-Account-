package com.developer.account.user.repository;

import com.developer.account.user.model.User;
import com.developer.account.user.model.VerificationToken;
import org.springframework.data.repository.ListCrudRepository;

import java.util.Optional;

public interface VerificationTokenRepository extends ListCrudRepository<VerificationToken, Long> {

    // Find a VerificationToken by its token value
    Optional<VerificationToken> findByToken(String token);

    // Delete all tokens associated with a specific user
    void deleteByUser(User user);
}
