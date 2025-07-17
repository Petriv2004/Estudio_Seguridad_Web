package com.example.injectionSQL.services;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import com.example.injectionSQL.models.User;
import com.example.injectionSQL.repositories.UserRepository;

@Service
public class UserService {
    @Autowired
    private UserRepository userRepository;

    public UserService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    public User loginVulnerable(String username, String password) {
        return userRepository.loginVulnerable(username, password);
    }

    public User loginSeguro(String username, String password) {
        return userRepository.findByUsernameAndPassword(username, password);
    }
}