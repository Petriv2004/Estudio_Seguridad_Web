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
import com.example.injectionSQL.components.LoginAttemptService;
import com.example.injectionSQL.models.LoginAttempt;
import com.example.injectionSQL.models.User;
import com.example.injectionSQL.services.UserService;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;

@RestController
@RequestMapping("/auth")
public class AuthController {
    @Autowired
    private UserService userService;

    @Autowired
    private JwtUtil jwtUtil;

    @Autowired
    private LoginAttemptService loginAttemptService;

    public AuthController(UserService userService, JwtUtil jwtUtil, LoginAttemptService loginAttemptService) {
        this.userService = userService;
        this.jwtUtil = jwtUtil;
        this.loginAttemptService = loginAttemptService;
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

    @PostMapping("/register")
    public ResponseEntity<?> registerUser(@RequestBody User user) {
        User registeredUser = userService.registUser(user);
        if (registeredUser != null) {
            return ResponseEntity.status(HttpStatus.CREATED).body("Usuario registrado exitosamente");
        } else {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("El usuario ya existe");
        }
    }

    @PostMapping("/login")
    public ResponseEntity<?> loginSeguro(@RequestBody User user) {
        User existingUser = userService.findUserByUsername(user.getUsername());
        if (existingUser != null) {
            User u = userService.loginSeguro(user.getUsername(), user.getPassword());
            if (u != null) {
                if (loginAttemptService.isBlocked(u.getUsername())) {
                    return ResponseEntity.status(HttpStatus.LOCKED)
                            .body("Usuario bloqueado por demasiados intentos fallidos");
                }
                loginAttemptService.loginSecceeded(u.getUsername());
                String token = jwtUtil.generateToken(u.getUsername(), u.getRole(), u.getId());
                HashMap<String, String> response = new HashMap<>();
                response.put("token", token);
                return ResponseEntity.ok(response);
            } else {
                loginAttemptService.loginFailed(user.getUsername());
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Login failed");
            }
        } else {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Usuario no encontrado");
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

    @GetMapping("/users/{id}")
    public ResponseEntity<?> getUserById(@PathVariable Integer id, @RequestHeader("Authorization") String authHeader) {
        String token = authHeader.replace("Bearer ", "");
        Integer userIdFromToken = jwtUtil.extractUserId(token);

        if (!id.equals(userIdFromToken)) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN)
                    .body("Acceso denegado: no puedes acceder a este usuario");
        }
        return ResponseEntity.ok(userService.findUserById(id));
    }
}
