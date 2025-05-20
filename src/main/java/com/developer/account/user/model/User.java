package com.developer.account.user.model;

import com.fasterxml.jackson.annotation.JsonIgnore;
import jakarta.persistence.*;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import lombok.*;

@Entity
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
@Table(name = "user")
public class User {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "id", nullable = false)
    private Long id;

    @NotBlank(message = "First name is required")
    @Column(name = "first_name", nullable = false)
    private String firstName;

    @NotBlank(message = "Surname is required")
    @Column(name = "surname", nullable = false)
    private String surname;

    @Email(message = "Email should be valid")
    @NotBlank(message = "Email is required")
    @Column(name = "email", nullable = false, unique = true, length = 320)
    private String email;

    @JsonIgnore
    @NotBlank(message = "Password is required")
    @Column(name = "password", nullable = false, length = 1000)
    private String password;

    @JsonIgnore
    @Transient // Not stored in the DB
    private String confirmPassword;

    @Column(name = "email_verified", nullable = false)
    private Boolean emailVerified = false;

    public boolean isEmailVerified() {

        return emailVerified;
    }
}
