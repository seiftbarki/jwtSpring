package com.auth.jwt.config;

import com.auth.jwt.user.User;
import jakarta.servlet.Filter;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfiguration {

    private final JwtAuthentificationFilter jwtAuthFilter;
    private final AuthenticationProvider authenticationProvider;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .csrf(AbstractHttpConfigurer::disable) // Désactive CSRF si nécessaire (API REST stateless)
                .authorizeHttpRequests(auth -> auth // Utilisation du lambda pour configurer les autorisations
                        .requestMatchers("/api/v1/auth/**").permitAll() // Permet l'accès à certaines ressources sans authentification
                        .anyRequest().authenticated() // Nécessite l'authentification pour toutes les autres requêtes
                )
                .sessionManagement(session -> session
                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS) // Définit une gestion de session sans état
                )
                .authenticationProvider(authenticationProvider) // Fournisseur d'authentification
                .addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter.class); // Ajoute le filtre JWT


        return http.build();
    }
}
