package employees.spring.security.exceptions;

import java.io.IOException;

import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpHeaders;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.access.AccessDeniedHandler;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@Configuration
public class SecurityExceptionsHandler implements AuthenticationEntryPoint, AccessDeniedHandler {

	@Override
	public void handle(HttpServletRequest request, HttpServletResponse response,
			AccessDeniedException accessDeniedException) throws IOException, ServletException {
		log.error("authorization error for {}", request.getContextPath());
		response.addHeader(HttpHeaders.ACCESS_CONTROL_ALLOW_ORIGIN, "*");
		response.setStatus(403);
	}

	@Override
	public void commence(HttpServletRequest request, HttpServletResponse response,
			AuthenticationException authException) throws IOException, ServletException {
		log.error("authentication authorization error for {}", request.getContextPath());
		response.addHeader(HttpHeaders.ACCESS_CONTROL_ALLOW_ORIGIN, "*");
		response.setStatus(401);
	}

}
