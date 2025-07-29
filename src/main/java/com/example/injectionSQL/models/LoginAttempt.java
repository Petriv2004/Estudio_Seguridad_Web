package com.example.injectionSQL.models;

import java.time.LocalDateTime;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import lombok.AllArgsConstructor;
import lombok.NoArgsConstructor;

@Entity
@NoArgsConstructor
@AllArgsConstructor
@Table(name = "loginAttempts")
public class LoginAttempt {
    @Id 
    private String username;
    @Column
    private int attempts;
    @Column
    private LocalDateTime lastAttempt;
    @Column
    private boolean locked;
    @Column
    private LocalDateTime lockTime;

    public String getUsername() {
        return username;
    }
    public void setUsername(String username) {
        this.username = username;
    }
    public int getAttempts() {
        return attempts;
    }
    public void setAttempts(int attempts) {
        this.attempts = attempts;
    }
    public LocalDateTime getLastAttempt() {
        return lastAttempt;
    }
    public void setLastAttempt(LocalDateTime lastAttempt) {
        this.lastAttempt = lastAttempt;
    }
    public boolean isLocked() {
        return locked;
    }
    public void setLocked(boolean locked) {
        this.locked = locked;
    }
    public LocalDateTime getLockTime() {
        return lockTime;
    }
    public void setLockTime(LocalDateTime lockTime) {
        this.lockTime = lockTime;
    }
}