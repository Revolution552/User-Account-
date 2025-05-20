package com.developer.account.user.dto;

public record UserResponseDto(
        Long id,
        String firstName,
        String surname,
        String email,
        boolean emailVerified
) {}