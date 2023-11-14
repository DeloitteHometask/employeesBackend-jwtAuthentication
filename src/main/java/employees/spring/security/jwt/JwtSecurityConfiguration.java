package employees.spring.security.jwt;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import employees.spring.security.RolesConfiguration;
import employees.spring.security.exceptions.SecurityExceptionsHandler;
import lombok.RequiredArgsConstructor;

@Configuration
@RequiredArgsConstructor
public class JwtSecurityConfiguration {
	final JwtFilter jwtFilter;
	final RolesConfiguration rolesConfiguration;
	final SecurityExceptionsHandler securityExceptionsHandler;
	
	@Bean
	@Order(5)
	SecurityFilterChain configure(HttpSecurity http) throws Exception {
		http.cors(custom -> custom.disable()).csrf(custom -> custom.disable())
		.exceptionHandling(custom -> custom
				.accessDeniedHandler(securityExceptionsHandler)
				.authenticationEntryPoint(securityExceptionsHandler))		
		.authorizeHttpRequests(custom -> custom.requestMatchers("accounts/login").permitAll());
		rolesConfiguration.configure(http);
		return http.httpBasic(Customizer.withDefaults())
				.addFilterBefore(jwtFilter, UsernamePasswordAuthenticationFilter.class).build();
	}
}
