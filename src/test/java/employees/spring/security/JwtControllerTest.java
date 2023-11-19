package employees.spring.security;

import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.springframework.http.MediaType;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import com.fasterxml.jackson.databind.ObjectMapper;

import employees.spring.security.controller.JwtController;
import employees.spring.security.dto.Account;
import employees.spring.security.jwt.JwtUtil;
import employees.spring.security.jwt.dto.LoginData;
import employees.spring.service.AccountService;

@ExtendWith(SpringExtension.class)
public class JwtControllerTest {

    private MockMvc mockMvc;

    @Mock
    private AccountService accountService;

    @Mock
    private PasswordEncoder passwordEncoder;

    @Mock
    private JwtUtil jwtUtil;

    @InjectMocks
    private JwtController jwtController;

    @BeforeEach
    public void setup() {
        mockMvc = MockMvcBuilders.standaloneSetup(jwtController).build();
    }

    @Test
    public void whenLoginWithValidCredentials_thenReturnsToken() throws Exception {
        String username = "user";
        String password = "password";
        LoginData loginData = new LoginData(username, password);
        Account account = new Account(username, password, new String[]{"USER"});
        String expectedToken = "token123";

        when(accountService.getAccount(username)).thenReturn(account);
        when(passwordEncoder.matches(password, account.getPassword())).thenReturn(true);
        when(jwtUtil.createToken(account)).thenReturn(expectedToken);

        mockMvc.perform(post("/accounts/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(new ObjectMapper().writeValueAsString(loginData)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.accessToken").value(expectedToken));
    }

    @Test
    public void whenLoginWithInvalidCredentials_thenThrowsException() throws Exception {
        String username = "user";
        String password = "wrongPassword";
        Account account = new Account(username, "correctPassword", new String[]{"USER"});

        when(accountService.getAccount(username)).thenReturn(account);
        when(passwordEncoder.matches(password, account.getPassword())).thenReturn(false);

    }
}
