package sn.ousoka.GestionFile;

import sn.ousoka.GestionFile.security.CustomUserDetailsService;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.GrantedAuthority;
import java.io.IOException;

import java.util.List;

@Configuration
public class SecurityConfig {

    @Bean
    public BCryptPasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public UserDetailsService userDetailsService(CustomUserDetailsService customUserDetailsService) {
        return customUserDetailsService;
    }

    @Bean
    public AuthenticationManager authenticationManager(UserDetailsService userDetailsService, BCryptPasswordEncoder passwordEncoder) {
        DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider();
        authProvider.setUserDetailsService(userDetailsService);
        authProvider.setPasswordEncoder(passwordEncoder);
        return new ProviderManager(List.of(authProvider));
    }

@Bean
public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
    http
        // .csrf().disable()
        .csrf(csrf -> csrf.disable()) 
        .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS)) // Mode stateless
        .authorizeHttpRequests(auth -> auth
            .requestMatchers("/login", "/home").permitAll()
            .requestMatchers("/api/login", "/api/public/**").permitAll() // Autoriser login
            .requestMatchers(org.springframework.http.HttpMethod.OPTIONS, "/**").permitAll() // Autoriser OPTIONS
            .requestMatchers("/client_home").hasAuthority("CLIENT")  // Use hasAuthority instead of hasRole
            .requestMatchers("/agent_home").hasAuthority("AGENT")    // Use hasAuthority instead of hasRole
            .requestMatchers("/admin_home").hasAuthority("ADMIN")    // Use hasAuthority instead of hasRole
            .anyRequest().permitAll()
        )
        .formLogin(form -> form
            .usernameParameter("numeroTel")
            .passwordParameter("password")
            .loginPage("/login")
            .failureUrl("/login?error=true")
            .permitAll()
            .successHandler((request, response, authentication) -> {
                // Check granted authorities (no 'ROLE_' prefix)
                authentication.getAuthorities().forEach(authority -> {
                    String role = authority.getAuthority();
                    System.out.println("Granted Authority: " + role);
                    
                    try {
                        if (role.equals("CLIENT")) {
                            response.sendRedirect("/client_home");
                        } else if (role.equals("AGENT")) {
                            response.sendRedirect("/agent_home");
                        } else if (role.equals("ADMIN")) {
                            response.sendRedirect("/admin_home");
                        }
                    } catch (IOException e) {
                        e.printStackTrace();
                    }
                });
            })
        )
        .logout(logout -> logout
            .logoutUrl("/logout")
            .logoutSuccessUrl("/home")
            .permitAll()
        );
    return http.build();
}


}
