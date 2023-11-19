package employees.spring.security.jwt;

import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Function;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import employees.spring.security.dto.Account;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;

@Component
public class JwtUtil {
	
	@Value("${app.jwt.signature.secret}")
	String key ;
	@Value("${app.jwt.expiration.period:7200000}")
	long expPeriod;
	
	public String extractUserName(String token) {
		return extractClaim(token, Claims::getSubject);
	}
	
	public String createToken(Account account) {
		return createToken(new HashMap<>(), account);
	}
	
	public Date extractExpirationDate(String token) {
		return extractClaim(token, Claims::getExpiration);
	}
	
	private Claims extractAllClaims(String token) {
		return Jwts.parserBuilder()
					.setSigningKey(getSigningKey())
					.build()
					.parseClaimsJws(token)
					.getBody();
	}

	private Key getSigningKey() {
		byte[]keyBytes = Decoders.BASE64.decode(key);
		return Keys.hmacShaKeyFor(keyBytes);
	}
	
	public <T> T extractClaim(String token, Function<Claims, T> claimResolver){
		return claimResolver.apply(extractAllClaims(token));
	}
	
	public String createToken(Map<String, Object> extraClaims, Account account) {
		String[]roles=account.getRoles();
		extraClaims.put("roles", roles);
		Date currentDate = new Date();
		Date expDate = new Date(System.currentTimeMillis() + expPeriod);
		return Jwts.builder()
					.addClaims(extraClaims)
					.setExpiration(expDate)
					.setIssuedAt(currentDate)
					.setSubject(account.getUsername())
					.signWith(getSigningKey(), SignatureAlgorithm.HS256)
					.compact();
	}
	
	@SuppressWarnings("unchecked")
	public List<String> extractRoles(String token) {
		return (List<String>) extractClaim(token, claims -> claims.get("roles"));
	}
}
