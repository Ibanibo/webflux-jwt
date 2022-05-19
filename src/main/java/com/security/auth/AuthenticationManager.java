package com.security.auth;

import java.util.Set;
import java.util.stream.Collectors;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Component;

import io.jsonwebtoken.Claims;
import reactor.core.publisher.Mono;

@Component
public class AuthenticationManager implements ReactiveAuthenticationManager {
    @Autowired
	private JwtTokenService jwtTokenService;

    @Override
    @SuppressWarnings("unchecked")
    public Mono<Authentication> authenticate(Authentication authentication) {
        String authToken = authentication.getCredentials().toString();
		String email = jwtTokenService.getEmailFromToken(authToken);
        return Mono.just(jwtTokenService.validateToken(authToken))
            .filter(valid -> valid)
            .switchIfEmpty(Mono.empty())
            .map(valid -> {
                Claims claims = jwtTokenService.getAllClaimsFromToken(authToken);
                Set<String> roleMap = claims.get("role", Set.class);
                return new UsernamePasswordAuthenticationToken(
					email,
					null,
					roleMap.stream().map(SimpleGrantedAuthority::new).collect(Collectors.toSet())
				);
            });
			
    }
    
}
