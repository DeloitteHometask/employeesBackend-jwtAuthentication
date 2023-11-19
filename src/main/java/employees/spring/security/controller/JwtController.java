package employees.spring.security.controller;

import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import employees.spring.NotFoundException;
import employees.spring.security.dto.Account;
import employees.spring.security.jwt.JwtUtil;
import employees.spring.security.jwt.dto.LoginData;
import employees.spring.security.jwt.dto.LoginResponse;
import employees.spring.service.AccountService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@RestController
@RequestMapping("accounts/login")
@RequiredArgsConstructor
@CrossOrigin
@Slf4j
public class JwtController {
	final AccountService accountService;
	final PasswordEncoder passwordEncoder;
	final JwtUtil jwtUtil;
	
	@PostMapping
	@CrossOrigin
	LoginResponse login(@RequestBody @Valid LoginData loginData) {
		try {
			log.debug("controller received username {}", loginData.username());
			String username = loginData.username();
			String password = loginData.password();
			
			Account account = accountService.getAccount(username);
			if (account == null) {
				throw new NotFoundException("Account with username " +username + " not found");
			}
			if(!passwordEncoder.matches(password, account.getPassword())) {
				throw new IllegalArgumentException("Wrong Credentials");
			}
			return new LoginResponse(jwtUtil.createToken(account));
			
		} catch(Exception e) {
			throw new NotFoundException("Wrong credentials: " + e.getMessage());
		}
	}
}
