package com.security.service;

import com.security.dao.UserRepository;
import com.security.model.User;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

@Service
public class UserService {
    @Autowired
    private UserRepository repository;

    public Mono<User> findById(Long id) {
        return repository.findById(id);
    }

    public Mono<User> findByEmail(String email) {
        return repository.findByEmail(email);
    }

    public Mono<User> create(User user) {
        return repository.save(user);
    }

    public Mono<User> update(User user) {
        return repository.save(user);
    }

    public Mono<Void> delete(Long id) {
        return repository.deleteById(id);
    }

    public Flux<User> findAll() {
        return repository.findAll();
    }
}
