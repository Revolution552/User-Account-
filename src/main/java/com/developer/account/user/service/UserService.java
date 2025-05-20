package com.developer.account.user.service;

import com.developer.account.user.dto.LoginRequest;
import com.developer.account.user.dto.RegisterRequest;
import com.developer.account.user.dto.UserResponseDto;
import com.developer.account.user.exception.EmailFailureException;
import com.developer.account.user.exception.EmailNotFoundException;
import com.developer.account.user.exception.UserAlreadyExistsException;
import com.developer.account.user.exception.UserNotVerifiedException;
import com.developer.account.user.model.PasswordResetToken;
import com.developer.account.user.model.User;
import com.developer.account.user.model.VerificationToken;
import com.developer.account.user.repository.PasswordResetTokenRepository;
import com.developer.account.user.repository.UserRepository;
import com.developer.account.user.repository.VerificationTokenRepository;

import jakarta.transaction.Transactional;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Optional;
import java.util.Random;
import java.util.stream.Collectors;

@Service
public class UserService {

    private static final Logger logger = LoggerFactory.getLogger(UserService.class);

    private final UserRepository userRepository;
    private final BCryptPasswordEncoder passwordEncoder;
    private final EmailService emailService;
    private final JWTService jwtService;
    private final VerificationTokenRepository verificationTokenRepository;
    private final PasswordResetTokenRepository passwordResetTokenRepository;

    @Autowired
    public UserService(
            UserRepository userRepository,
            BCryptPasswordEncoder passwordEncoder,
            EmailService emailService,
            JWTService jwtService,
            VerificationTokenRepository verificationTokenRepository,
            PasswordResetTokenRepository passwordResetTokenRepository
    ) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.emailService = emailService;
        this.jwtService = jwtService;
        this.verificationTokenRepository = verificationTokenRepository;
        this.passwordResetTokenRepository = passwordResetTokenRepository;
    }

    // --- Admin Methods ---
    public List<UserResponseDto> getAllUsersForAdmin() {
        return userRepository.findAll()
                .stream()
                .map(user -> new UserResponseDto(
                        user.getId(),
                        user.getFirstName(),
                        user.getSurname(),
                        user.getEmail(),
                        user.isEmailVerified()
                ))
                .collect(Collectors.toList());
    }

    public Optional<UserResponseDto> getUserByIdForAdmin(Long id) {
        return userRepository.findById(id)
                .map(user -> new UserResponseDto(
                        user.getId(),
                        user.getFirstName(),
                        user.getSurname(),
                        user.getEmail(),
                        user.isEmailVerified()
                ));
    }

    // --- Public Methods ---
    public User registerUser(RegisterRequest request) throws UserAlreadyExistsException, EmailFailureException {
        logger.info("Attempting to register user with email: {}", request.getEmail());

        if (userRepository.findByEmailIgnoreCase(request.getEmail()).isPresent()) {
            throw new UserAlreadyExistsException("User already exists with email: " + request.getEmail());
        }

        User user = new User();
        user.setFirstName(request.getFirstName());
        user.setSurname(request.getSurname());
        user.setEmail(request.getEmail());
        user.setPassword(passwordEncoder.encode(request.getPassword()));
        user.setEmailVerified(false);

        user = userRepository.save(user);
        VerificationToken verificationToken = createVerificationToken(user);
        emailService.sendVerificationEmail(verificationToken);

        return user;
    }

    // --- Private Helper Methods ---
    private VerificationToken createVerificationToken(User user) {
        VerificationToken token = new VerificationToken();
        token.setUser(user);
        token.setToken(generateSixDigitCode());
        token.generateTimestamps(1); // 1 hour expiry
        return verificationTokenRepository.save(token);
    }

    private PasswordResetToken createPasswordResetToken(User user) {
        PasswordResetToken token = new PasswordResetToken();
        token.setUser(user);
        token.setToken(generateSixDigitCode());
        token.generateTimestamps(30); // 30 minutes expiry
        return passwordResetTokenRepository.save(token);
    }

    private String generateSixDigitCode() {
        return String.format("%06d", new Random().nextInt(900000) + 100000);
    }


    public String loginUser(LoginRequest request) throws UserNotVerifiedException, EmailFailureException {
        logger.info("Login attempt for email: {}", request.getEmail());

        Optional<User> userOptional = userRepository.findByEmail(request.getEmail());
        if (userOptional.isPresent()) {
            User user = userOptional.get();

            if (!user.isEmailVerified()) {
                // Resend verification email
                VerificationToken token = createVerificationToken(user);
                emailService.sendVerificationEmail(token);  // can throw EmailFailureException

                logger.warn("Login failed - user not verified: {}", request.getEmail());
                throw new UserNotVerifiedException(true);
            }

            if (passwordEncoder.matches(request.getPassword(), user.getPassword())) {
                String jwt = jwtService.generateJWT(user);  // Now calling your JWTService
                logger.info("Login successful for email: {}", request.getEmail());
                return jwt;
            }
        }

        logger.warn("Login failed - invalid credentials: {}", request.getEmail());
        return null;
    }

    @Transactional
    public boolean verifyUser(String token) {
        Optional<VerificationToken> opToken = verificationTokenRepository.findByToken(token);
        if (opToken.isPresent()) {
            VerificationToken verificationToken = opToken.get();
            User user = verificationToken.getUser();
            if (!user.isEmailVerified()) {
                user.setEmailVerified(true);
                userRepository.save(user);
                verificationTokenRepository.deleteByUser(user);
                logger.info("User verified successfully: {}", user.getEmail());
                return true;
            }
        }
        logger.warn("Verification failed for token: {}", token);
        return false;
    }

    public void forgotPassword(String email) throws EmailNotFoundException, EmailFailureException {
        Optional<User> opUser = userRepository.findByEmailIgnoreCase(email);
        if (opUser.isPresent()) {
            User user = opUser.get();

            PasswordResetToken token = createPasswordResetToken(user);

            try {
                emailService.sendPasswordResetEmail(user, token.getToken());
                logger.info("Password reset email sent successfully to: {}", email);
            } catch (EmailFailureException e) {
                logger.error("Failed to send password reset email to: {}", email, e);
                throw e;
            }
        } else {
            logger.warn("Email not found for password reset: {}", email);
            throw new EmailNotFoundException("No user found with email: " + email);
        }
    }

    public boolean resetPasswordWithToken(String token, String newPassword, String confirmPassword) {
        if (!newPassword.equals(confirmPassword)) {
            logger.warn("Password reset failed - passwords do not match for token: {}", token);
            throw new IllegalArgumentException("New password and confirmation password do not match.");
        }

        Optional<PasswordResetToken> tokenOpt = passwordResetTokenRepository.findByToken(token);

        if (tokenOpt.isEmpty()) {
            logger.warn("Password reset failed - invalid token: {}", token);
            throw new IllegalArgumentException("Invalid or expired token.");
        }

        PasswordResetToken resetToken = tokenOpt.get();

        if (resetToken.isExpired()) {
            logger.warn("Password reset failed - token expired: {}", token);
            throw new IllegalArgumentException("Reset token has expired.");
        }

        User user = resetToken.getUser();
        user.setPassword(passwordEncoder.encode(newPassword));
        userRepository.save(user);

        passwordResetTokenRepository.delete(resetToken);

        logger.info("Password reset successfully for token: {}", token);
        return true;
    }
}
