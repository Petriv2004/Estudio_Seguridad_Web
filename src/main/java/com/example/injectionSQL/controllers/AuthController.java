package com.example.injectionSQL.controllers;

import java.util.HashMap;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.example.injectionSQL.components.JwtUtil;
import com.example.injectionSQL.models.User;
import com.example.injectionSQL.services.UserService;
import org.springframework.web.bind.annotation.GetMapping;

@RestController
@RequestMapping("/auth")
public class AuthController {
    @Autowired
    private UserService userService;

    @Autowired
    private JwtUtil jwtUtil;

    public AuthController(UserService userService, JwtUtil jwtUtil) {
        this.userService = userService;
        this.jwtUtil = jwtUtil;
    }

    @PostMapping("/login/vulnerable")
    public ResponseEntity<String> loginVulnerable(@RequestBody User user) {
        User u = userService.loginVulnerable(user.getUsername(), user.getPassword());
        if (u != null) {
            return ResponseEntity.ok("Login successful");
        } else {
            return ResponseEntity.status(401).body("Login failed");
        }
    }

    @PostMapping("/login")
    public ResponseEntity<?> loginSeguro(@RequestBody User user) {
        User u = userService.loginSeguro(user.getUsername(), user.getPassword());
        if (u != null) {
            String token = jwtUtil.generateToken(u.getUsername(), u.getRole());
            HashMap<String, String> response = new HashMap<>();
            response.put("token", token);
            return ResponseEntity.ok(response);
        } else {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Login failed");
        }
    }

    @GetMapping("/secure")
    public ResponseEntity<?> secureEndpoint(@RequestHeader("Authorization") String authHeader) {
        try {
            String token = authHeader.replace("Bearer ", "");
            String username = jwtUtil.extractUsername(token);

            if (jwtUtil.isTokenValid(token, username)) {
                return ResponseEntity.ok("Acceso concedido a " + username);
            } else {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Token inválido o expirado");
            }
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Token inválido o malformado");
        }
    }

    @GetMapping("/admin")
    public ResponseEntity<?> adminEndpoint(@RequestHeader("Authorization") String authHeader) {
        String token = authHeader.replace("Bearer ", "");
        String username = jwtUtil.extractUsername(token);
        String role = jwtUtil.extractUserRole(token);

        if (jwtUtil.isTokenValid(token, username) && "Admin".equals(role)) {
            return ResponseEntity.ok("Acceso al panel de administración concedido");
        } else {
            return ResponseEntity.status(HttpStatus.FORBIDDEN).body("Acceso denegado: requiere rol ADMIN");
        }
    }

    @GetMapping("/user")
    public ResponseEntity<?> userEndpoint(@RequestHeader("Authorization") String authHeader) {
        String token = authHeader.replace("Bearer ", "");
        String username = jwtUtil.extractUsername(token);
        String role = jwtUtil.extractUserRole(token);

        if (jwtUtil.isTokenValid(token, username) && "User".equals(role)) {
            return ResponseEntity.ok("Bienvenido usuario " + username);
        } else {
            return ResponseEntity.status(HttpStatus.FORBIDDEN).body("Acceso denegado: requiere rol USER");
        }
    }
}
