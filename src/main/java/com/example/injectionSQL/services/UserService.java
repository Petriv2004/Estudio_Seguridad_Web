package com.example.injectionSQL.services;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.bcrypt.BCrypt;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import com.example.injectionSQL.models.User;
import com.example.injectionSQL.repositories.UserRepository;

@Service
public class UserService {
    @Autowired
    private UserRepository userRepository;
    @Autowired
    private PasswordEncoder passwordEncoder;

    public UserService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    public User registUser (User user) {
        User existingUser = userRepository.findByUsername(user.getUsername());
        if (existingUser != null) {
            return null;
        }
        user.setPassword(passwordEncoder.encode(user.getPassword()));
        return userRepository.save(user);
    }

    public User loginVulnerable(String username, String password) {
        return userRepository.loginVulnerable(username, password);
    }

    public User loginSeguro(String username, String password) {
        User user = userRepository.findByUsername(username);
        if(user != null){
            BCryptPasswordEncoder passwordEncoder = new BCryptPasswordEncoder();
            if(passwordEncoder.matches(password, user.getPassword())){
                return user;
            }
        }
        return null;
    }

    public User findUserById(Integer id) {
        return userRepository.findById(id).orElse(null);
    }

    public User findUserByUsername(String username) {
        return userRepository.findByUsername(username);
    }
}