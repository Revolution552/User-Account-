package com.developer.account;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;


@SpringBootApplication(exclude = {
		org.springframework.boot.autoconfigure.security.servlet.UserDetailsServiceAutoConfiguration.class
})
public class AccountApplication {

	public static void main(String[] args) {
		SpringApplication.run(AccountApplication.class, args);
	}

}
