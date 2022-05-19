package com.security;

import com.security.auth.JwtTokenService;
import com.security.model.User;
import com.security.payload.AuthRequest;
import com.security.payload.AuthResponse;
import com.security.service.UserService;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

@RestController
public class UserController {
    @Autowired
    private UserService service;
    @Autowired
    private PasswordEncoder passwordEncoder;
    @Autowired
    private JwtTokenService jwtTokenService;

    @PostMapping("/login")
    public Mono<ResponseEntity<AuthResponse>> login(@RequestBody AuthRequest authRequest) {
        return service.findByEmail(authRequest.getEmail())
            //.filter(UserDetails -> passwordEncoder.encode(authRequest.getPassword()).equals(UserDetails.getPassword()))
            .filter(UserDetails -> passwordEncoder.matches(authRequest.getPassword(), UserDetails.getPassword()))
            .map(UserDetails -> ResponseEntity.ok(new AuthResponse(jwtTokenService.generateToken(UserDetails))))
            .switchIfEmpty(Mono.just(ResponseEntity.status(HttpStatus.BAD_REQUEST).build()));
    }

    @PostMapping("/login1")
	public Mono<ResponseEntity<?>> login1(@RequestBody AuthRequest authRequest) {
		return service.findByEmail(authRequest.getEmail())
				.map((user) -> {
					if(passwordEncoder.matches(authRequest.getPassword(), user.getPassword())) {
						return ResponseEntity.ok(new AuthResponse(jwtTokenService.generateToken(user)));
					}else {
						System.out.println("Failed");
						return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
					}

				}).defaultIfEmpty(ResponseEntity.status(HttpStatus.UNAUTHORIZED).build());
	}

    @PostMapping("/create") 
    @ResponseStatus(HttpStatus.CREATED)
    public Mono<User> create(@RequestBody User user) {
       return service.create(user);
    }

    @GetMapping(value = "/get/all", produces = MediaType.TEXT_EVENT_STREAM_VALUE)
    @ResponseBody
    public Flux<User> findAll() {
        return service.findAll();
    }

    @GetMapping("/get/{id}")
    @ResponseBody
    public ResponseEntity<Mono<User>> findById(@PathVariable("id") Long id) {
        Mono<User> user = service.findById(id);
        return new ResponseEntity<Mono<User>>(user, user != null ? HttpStatus.OK : HttpStatus.NOT_FOUND);
    }

    @PutMapping("/update")
    @ResponseStatus(HttpStatus.OK)
    public Mono<User> update(@RequestBody User user) {
        return service.update(user);
    }

    @DeleteMapping("/delete/{id}")
    @ResponseStatus(HttpStatus.OK)
    public void delete(@PathVariable("id") Long id) {
        service.delete(id).subscribe();
    }
}
