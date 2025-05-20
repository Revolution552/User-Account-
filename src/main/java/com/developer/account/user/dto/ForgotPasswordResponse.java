package com.developer.account.user.dto;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class ForgotPasswordResponse {
    private boolean success;
    private String message;

}
