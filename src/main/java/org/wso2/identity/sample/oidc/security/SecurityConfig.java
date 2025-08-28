package org.wso2.identity.sample.oidc.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.*;
import java.util.stream.Collectors;
import java.util.stream.Stream;

@Configuration
public class SecurityConfig {

    @Bean
    SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .csrf(csrf -> csrf.disable())
                .cors(Customizer.withDefaults())
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/actuator/health", "/actuator/info").permitAll()
                        .requestMatchers(HttpMethod.OPTIONS, "/**").permitAll()

                        // require API scopes
                        .requestMatchers("/hello").hasAuthority("SCOPE_hello.read")
                        .requestMatchers("/helloRestrict").hasAuthority("SCOPE_hello.admin")

                        .anyRequest().authenticated()
                )
                .oauth2ResourceServer(oauth -> oauth
                        .jwt(jwt -> jwt.jwtAuthenticationConverter(jwtAuthConverter()))
                );

        return http.build();
    }

    // Combine default SCOPE_* authorities + ROLE_* from groups/roles
    private JwtAuthenticationConverter jwtAuthConverter() {
        JwtAuthenticationConverter conv = new JwtAuthenticationConverter();

        // default converter produces SCOPE_* from "scope"/"scp"
        JwtGrantedAuthoritiesConverter scopeConv = new JwtGrantedAuthoritiesConverter();

        conv.setJwtGrantedAuthoritiesConverter((Jwt jwt) -> {
            // 1) scopes -> SCOPE_*
            Collection<GrantedAuthority> scopes = scopeConv.convert(jwt);

            // 2) groups/roles -> ROLE_*
            List<String> fromGroups = Optional.ofNullable(jwt.getClaimAsStringList("groups")).orElse(List.of());
            List<String> fromRoles  = Optional.ofNullable(jwt.getClaimAsStringList("roles")).orElse(List.of());

            Collection<GrantedAuthority> roles = Stream.of(fromGroups, fromRoles)
                    .flatMap(Collection::stream)
                    .map(s -> s.substring(s.lastIndexOf('/') + 1))    // trim "Default/ADMIN" -> "ADMIN"
                    .map(s -> s.toUpperCase(Locale.ROOT))
                    .distinct()
                    .map(r -> new SimpleGrantedAuthority("ROLE_" + r))
                    .collect(Collectors.toList());

            // merge
            return Stream.concat(scopes.stream(), roles.stream()).collect(Collectors.toSet());
        });

        return conv;
    }

    @Bean
    CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration cfg = new CorsConfiguration();
        cfg.setAllowedOriginPatterns(List.of("http://localhost:4200"));
        cfg.setAllowedMethods(List.of("GET", "POST", "PUT", "DELETE", "OPTIONS"));
        cfg.setAllowedHeaders(List.of("*"));
        cfg.setExposedHeaders(List.of("Authorization"));
        cfg.setAllowCredentials(false);
        cfg.setMaxAge(3600L);

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", cfg);
        return source;
    }
}