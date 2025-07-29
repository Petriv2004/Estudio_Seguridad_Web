package com.example.injectionSQL.components;

import java.time.Duration;
import java.time.LocalDateTime;
import java.util.Optional;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import com.example.injectionSQL.models.LoginAttempt;
import com.example.injectionSQL.repositories.LoginAttemptRepository;

@Component
public class LoginAttemptService {
    private final int MAX_ATTEMPTS = 5;
    private final int LOCK_TIME_MINUTES = 15;

    @Autowired
    private LoginAttemptRepository loginAttemptRepository;

    public void loginSecceeded(String username){
        loginAttemptRepository.deleteById(username);
    }

    public void loginFailed(String username){
        LoginAttempt attempt = loginAttemptRepository.findById(username).orElse(new LoginAttempt());

        attempt.setUsername(username);
        attempt.setAttempts(attempt.getAttempts() + 1);
        attempt.setLastAttempt(LocalDateTime.now());

        if(attempt.getAttempts() >= MAX_ATTEMPTS) {
            attempt.setLocked(true);
            attempt.setLockTime(LocalDateTime.now());
        }

        loginAttemptRepository.save(attempt);
    }

    public boolean isBlocked(String username){
        Optional <LoginAttempt> optional = loginAttemptRepository.findById(username);
        if(optional.isEmpty()) {
            return false;
        }
        LoginAttempt attempt = optional.get();

        if(attempt.isLocked()){
            if(Duration.between(attempt.getLockTime(), LocalDateTime.now()).toMinutes() >= LOCK_TIME_MINUTES) {
                loginAttemptRepository.deleteById(username);
                return false;
            } 
            return true;
        }
        return false;
    }
}
