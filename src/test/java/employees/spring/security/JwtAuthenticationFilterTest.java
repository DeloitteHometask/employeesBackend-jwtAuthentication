package employees.spring.security;

import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.web.servlet.MockMvc;

import com.fasterxml.jackson.databind.ObjectMapper;

import employees.spring.security.controller.JwtController;
import employees.spring.security.exceptions.SecurityExceptionsHandler;
import employees.spring.security.jwt.JwtFilter;
import employees.spring.security.jwt.JwtSecurityConfiguration;
import employees.spring.security.jwt.JwtUtil;
import employees.spring.security.jwt.dto.LoginData;
import employees.spring.security.jwt.dto.LoginResponse;

@SpringBootApplication
class RolesConfigurationTest implements RolesConfiguration {

	@Override
	public void configure(HttpSecurity httpSecurity) throws Exception {
		httpSecurity.authorizeHttpRequests(
				custom -> custom.requestMatchers(HttpMethod.GET).authenticated().anyRequest().hasRole("ADMIN_TEST"));
	}
}

@WebMvcTest({ JwtFilter.class, JwtUtil.class, JwtController.class, JwtSecurityConfiguration.class,
		AccountingConfiguration.class, RolesConfigurationTest.class, SecurityExceptionsHandler.class })
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
class JwtAuthenticationFilterTest {
	static String jwt;
	@Autowired
	MockMvc mockMvc;
	@Autowired
	JwtFilter jwtFilter;
	@Autowired
	JwtUtil jwtUtil;

	@MockBean
	private UserDetailsService userDetailsService;
	@MockBean
	private PasswordEncoder passwordEncoder;

	ObjectMapper mapper = new ObjectMapper();
	LoginData loginData = new LoginData("admin", "pppp");

	@BeforeEach
	void setUp() {
		UserDetails userDetails = User.builder().username("admin").password("encodedPassword").authorities("ADMIN_TEST")
				.build();

		when(userDetailsService.loadUserByUsername("admin")).thenReturn(userDetails);
		when(passwordEncoder.matches(eq("pppp"), anyString())).thenReturn(true);
	}

	@Test
	void authenticationErrorTest() throws Exception {
		mockMvc.perform(get("/kuku")).andDo(print()).andExpect(status().isUnauthorized());
	}

	@Test
	@Order(1)
	void loginTest() throws Exception {
		String loginResponseJson = mockMvc
				.perform(post("/accounts/login").contentType(MediaType.APPLICATION_JSON)
						.content(mapper.writeValueAsString(loginData)))
				.andDo(print()).andExpect(status().isOk()).andReturn().getResponse().getContentAsString();
		LoginResponse loginResponse = mapper.readValue(loginResponseJson, LoginResponse.class);
		jwt = loginResponse.accessToken();
	}

	@Test
	@Order(2)
	void authenticationNormalTest() throws Exception {
		mockMvc.perform(get("/accounts/kuku").header("Authorization", "Bearer " + jwt)).andDo(print())
				.andExpect(status().isNotFound());
	}

	@Test
	@Order(3)
	void authenticationExpiredTest() throws Exception {
		Thread.sleep(2500);
		mockMvc.perform(get("/accounts/kuku").header("Authorization", "Bearer " + jwt)).andDo(print())
				.andExpect(status().isUnauthorized());
	}

	@Test
	@Order(4)
	void successfulAuthenticationWithJwtTokenTest() throws Exception {
		UserDetails userDetails = User.builder().username("admin").password("encodedPassword").authorities("ADMIN_TEST")
				.build();

		when(userDetailsService.loadUserByUsername("admin")).thenReturn(userDetails);

		mockMvc.perform(get("/accounts/login")
				.header("Authorization", "Bearer " + jwt)).andDo(print()).andExpect(status().isOk());
	}

	@Test
	@Order(5)
	void accessDeniedForInvalidRoleTest() throws Exception {
		UserDetails userDetails = User.builder().username("user").password("encodedPassword").authorities("USER")
				.build();

		String invalidRoleJwt = jwtUtil.createToken(userDetails);

		mockMvc.perform(get("/accounts/login")
				.header("Authorization", "Bearer " + invalidRoleJwt)).andDo(print()).andExpect(status().isForbidden());
	}
}
