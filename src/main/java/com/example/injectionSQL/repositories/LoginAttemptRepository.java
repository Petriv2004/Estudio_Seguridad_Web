package com.example.injectionSQL.repositories;

import org.springframework.data.jpa.repository.JpaRepository;

import com.example.injectionSQL.models.LoginAttempt;

public interface LoginAttemptRepository extends JpaRepository<LoginAttempt, String> {
    
}
