package com.security.auth;

import java.security.Key;
import java.util.Date;

import javax.annotation.PostConstruct;

import com.security.model.User;

import org.springframework.stereotype.Component;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtBuilder;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;

/**
* @author Christian
*/
@Component
public class JwtTokenService {
    /**
	* THIS IS NOT A SECURE PRACTICE! For simplicity, we are storing a static key here. Ideally, in a
	* microservices environment, this key would be kept on a config-server.
	*/
    private String secret = "ThisIsTheSecretForJwtHS256SignatureAlgorithm";
    private Key key;
    private long expirationInMilliseconds; //= 7200000; //1hr 3600000;

    @PostConstruct
	public void init() {
		//key = Base64.getEncoder().encodeToString(key.getBytes());
        //key = Keys.hmacShaKeyFor
        this.key = Keys.hmacShaKeyFor(secret.getBytes());
	}

    public String generateToken(User user) {
        long nowMillis = System.currentTimeMillis();
        Date now = new Date(nowMillis);
        JwtBuilder builder = Jwts.builder()
                .setId(String.valueOf(user.getId()))
                .setSubject(user.getEmail())
                .setIssuedAt(now)
                .signWith(key)
                .claim("roles", user.getRoles());
        if (expirationInMilliseconds > 0) {
            builder.setExpiration(new Date(nowMillis + expirationInMilliseconds));
        }
        return builder.compact();
    }

    public Claims getAllClaimsFromToken(String token) {
		return Jwts.parserBuilder()
            .setSigningKey(key)
            .build()
            .parseClaimsJws(token)
            .getBody();
	}

    public Long getUserIdFromToken(String token) {
        Claims claims = getAllClaimsFromToken(token);
        return Long.parseLong(claims.getId());
    }

    public String getEmailFromToken(String token) {
        return getAllClaimsFromToken(token)
            .getSubject();
    }

    public Boolean validateToken(String token) {
		return !isTokenExpired(token);
	}

    private Boolean isTokenExpired(String token) {
		final Date expiration = getExpirationDateFromToken(token);
		return expiration.before(new Date());
	}

    private Date getExpirationDateFromToken(String token) {
		return getAllClaimsFromToken(token).getExpiration();
	}
}
