package com.example.injectionSQL.repositories;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import com.example.injectionSQL.models.User;

public interface UserRepository extends JpaRepository<User, Integer> {
    //Esta es la version vulnerable a inyecciones SQL
    @Query(value = "SELECT * FROM users WHERE username = ?1 AND password = ?2", nativeQuery = true)
    User loginVulnerable (String username, String password);

    // Esta es la version segura contra inyecciones SQL
     @Query(value = "SELECT * FROM users WHERE username = :username AND password = :password", nativeQuery = true)
     User loginSecure(@Param("username") String username, @Param("password") String password);

     User findByUsernameAndPassword(String username, String password);
}
