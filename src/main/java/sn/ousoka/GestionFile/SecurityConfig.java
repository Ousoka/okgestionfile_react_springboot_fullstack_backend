// package sn.ousoka.GestionFile;

// import sn.ousoka.GestionFile.security.CustomUserDetailsService;
// import org.springframework.context.annotation.Bean;
// import org.springframework.context.annotation.Configuration;
// import org.springframework.security.authentication.AuthenticationManager;
// import org.springframework.security.authentication.ProviderManager;
// import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
// import org.springframework.security.config.annotation.web.builders.HttpSecurity;
// import org.springframework.security.config.http.SessionCreationPolicy;
// import org.springframework.security.core.userdetails.UserDetailsService;
// import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
// import org.springframework.security.web.SecurityFilterChain;
// import org.springframework.web.cors.CorsConfiguration;
// import org.springframework.web.cors.CorsConfigurationSource;
// import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

// import javax.servlet.http.HttpServletResponse; // Added missing import
// import java.util.Arrays;
// import java.util.List;

// @Configuration
// public class SecurityConfig {

//     @Bean
//     public BCryptPasswordEncoder passwordEncoder() {
//         return new BCryptPasswordEncoder();
//     }

//     @Bean
//     public UserDetailsService userDetailsService(CustomUserDetailsService customUserDetailsService) {
//         return customUserDetailsService;
//     }

//     @Bean
//     public AuthenticationManager authenticationManager(UserDetailsService userDetailsService, BCryptPasswordEncoder passwordEncoder) {
//         DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider();
//         authProvider.setUserDetailsService(userDetailsService);
//         authProvider.setPasswordEncoder(passwordEncoder);
//         return new ProviderManager(List.of(authProvider));
//     }

//     @Bean
//     public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
//         http
//             .csrf(csrf -> csrf.disable()) // Disable CSRF for REST API
//             .cors(cors -> cors.configurationSource(corsConfigurationSource())) // Enable CORS
//             .sessionManagement(session -> session
//                 .sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED) // Use sessions only when needed
//             )
//             .authorizeHttpRequests(auth -> auth
//                 .requestMatchers("/api/login", "/api/", "/api/home").permitAll() // Public API endpoints
//                 .requestMatchers(org.springframework.http.HttpMethod.OPTIONS, "/**").permitAll() // Allow CORS preflight
//                 .requestMatchers("/api/client_home").hasAuthority("CLIENT")
//                 .requestMatchers("/api/agent_home").hasAuthority("AGENT")
//                 .requestMatchers("/api/admin").hasAuthority("ADMIN")
//                 .anyRequest().authenticated() // Require authentication for other endpoints
//             )
//             .formLogin(form -> form.disable()) // Disable form login for REST API
//             .logout(logout -> logout
//                 .logoutUrl("/api/logout")
//                 .logoutSuccessUrl("/api/")
//                 .invalidateHttpSession(true)
//                 .deleteCookies("JSESSIONID")
//                 .permitAll()
//             )
//             .exceptionHandling(ex -> ex
//                 .authenticationEntryPoint((request, response, authException) -> {
//                     response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Unauthorized");
//                 })
//             );

//         return http.build();
//     }

//     @Bean
//     public CorsConfigurationSource corsConfigurationSource() {
//         CorsConfiguration configuration = new CorsConfiguration();
//         configuration.setAllowedOrigins(Arrays.asList("https://okgestionfile-react-springboot-fullstack.onrender.com"));
//         configuration.setAllowedMethods(Arrays.asList("GET", "POST", "PUT", "DELETE", "OPTIONS"));
//         configuration.setAllowedHeaders(Arrays.asList("*"));
//         configuration.setAllowCredentials(true); // Allow cookies/session for session-based auth
//         UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
//         source.registerCorsConfiguration("/**", configuration);
//         return source;
//     }
// }


// package sn.ousoka.GestionFile;

// // import org.springframework.boot.web.servlet.server.SessionCookieConfig;
// import sn.ousoka.GestionFile.security.CustomUserDetailsService;
// import org.springframework.context.annotation.Bean;
// import org.springframework.context.annotation.Configuration;
// import org.springframework.security.authentication.AuthenticationManager;
// import org.springframework.security.authentication.ProviderManager;
// import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
// import org.springframework.security.config.annotation.web.builders.HttpSecurity;
// import org.springframework.security.config.http.SessionCreationPolicy;
// import org.springframework.security.core.userdetails.UserDetailsService;
// import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
// import org.springframework.security.web.SecurityFilterChain;
// import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
// import org.springframework.web.cors.CorsConfiguration;
// import org.springframework.web.cors.CorsConfigurationSource;
// import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

// import javax.servlet.http.HttpServletResponse;
// import java.util.Arrays;
// import java.util.List;

// @Configuration
// public class SecurityConfig {

//     @Bean
//     public BCryptPasswordEncoder passwordEncoder() {
//         return new BCryptPasswordEncoder();
//     }

//     @Bean
//     public UserDetailsService userDetailsService(CustomUserDetailsService customUserDetailsService) {
//         return customUserDetailsService;
//     }

//     @Bean
//     public AuthenticationManager authenticationManager(UserDetailsService userDetailsService, BCryptPasswordEncoder passwordEncoder) {
//         DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider();
//         authProvider.setUserDetailsService(userDetailsService);
//         authProvider.setPasswordEncoder(passwordEncoder);
//         return new ProviderManager(List.of(authProvider));
//     }

//     // Configure session cookie attributes
//     @Bean
//     public org.springframework.boot.web.server.CookieSessionConfigurer cookieSessionConfigurer() {
//         return new org.springframework.boot.web.server.CookieSessionConfigurer() {
//             @Override
//             public void configure(org.springframework.boot.web.server.SessionCookieConfig sessionCookieConfig) {
//                 sessionCookieConfig.setHttpOnly(true);
//                 sessionCookieConfig.setSecure(true);
//                 sessionCookieConfig.setSameSite("None");
//                 sessionCookieConfig.setPath("/");
//             }
//         };
//     }

//     @Bean
//     public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
//         http
//             .csrf(csrf -> csrf
//                 .ignoringRequestMatchers("/api/login", "/api/logout") // Disable CSRF for login/logout
//                 .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse()) // Use cookies for CSRF tokens
//             )
//             .cors(cors -> cors.configurationSource(corsConfigurationSource())) // Enable CORS
//             .sessionManagement(session -> session
//                 .sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED) // Use sessions only when needed
//                 .maximumSessions(1) // Allow only one session per user
//                 .maxSessionsPreventsLogin(false) // Prevent new logins if the user already has a session
//             )
//             .authorizeHttpRequests(auth -> auth
//                 .requestMatchers("/api/login", "/api/", "/api/home").permitAll() // Public API endpoints
//                 .requestMatchers(org.springframework.http.HttpMethod.OPTIONS, "/**").permitAll() // Allow CORS preflight
//                 .requestMatchers("/api/client_home", "/api/client_view_tickets", "/api/client_obtain_ticket").hasAuthority("CLIENT") // Protect client-specific endpoints
//                 .requestMatchers("/api/agent_home").hasAuthority("AGENT") // Protect agent-specific endpoints
//                 .requestMatchers("/api/admin").hasAuthority("ADMIN") // Protect admin-specific endpoints
//                 .anyRequest().authenticated() // Require authentication for other endpoints
//             )
//             .formLogin(form -> form.disable()) // Disable form login for REST API
//             .logout(logout -> logout
//                 .logoutUrl("/api/logout")
//                 .logoutSuccessUrl("/api/")
//                 .invalidateHttpSession(true)
//                 .deleteCookies("JSESSIONID")
//                 .permitAll()
//             )
//             .exceptionHandling(ex -> ex
//                 .authenticationEntryPoint((request, response, authException) -> {
//                     response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Unauthorized");
//                 })
//             );

//         return http.build();
//     }

//     @Bean
//     public CorsConfigurationSource corsConfigurationSource() {
//         CorsConfiguration configuration = new CorsConfiguration();
//         configuration.setAllowedOrigins(Arrays.asList("https://okgestionfile-react-springboot-fullstack.onrender.com")); // Allow your frontend origin
//         configuration.setAllowedMethods(Arrays.asList("GET", "POST", "PUT", "DELETE", "OPTIONS")); // Allow all HTTP methods
//         configuration.setAllowedHeaders(Arrays.asList("*")); // Allow all headers
//         configuration.setAllowCredentials(true); // Allow cookies/session for session-based auth
//         UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
//         source.registerCorsConfiguration("/**", configuration); // Apply CORS to all endpoints
//         return source;
//     }
// }


//----------------------------------------------------------------------------------

package sn.ousoka.GestionFile;

import sn.ousoka.GestionFile.security.CustomUserDetailsService;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import jakarta.servlet.http.HttpServletResponse;
import java.util.Arrays;
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

    // @Bean
    // public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
    //     http
    //         .csrf(csrf -> csrf
    //             .ignoringRequestMatchers("/api/login", "/api/logout")
    //             .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
    //         )
    //         .cors(cors -> cors.configurationSource(corsConfigurationSource()))
    //         .sessionManagement(session -> session
    //             .sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED)
    //             .maximumSessions(1)
    //             .maxSessionsPreventsLogin(false)
    //         )
    //         .authorizeHttpRequests(auth -> auth
    //             .requestMatchers("/api/login", "/api/", "/api/home").permitAll()
    //             .requestMatchers(org.springframework.http.HttpMethod.OPTIONS, "/**").permitAll()
    //             .requestMatchers("/api/client_home", "/api/client_view_tickets", "/api/client_obtain_ticket").hasAuthority("CLIENT")
    //             .requestMatchers("/api/agent_home").hasAuthority("AGENT")
    //             .requestMatchers("/api/admin").hasAuthority("ADMIN")
    //             .anyRequest().authenticated()
    //         )
    //         .formLogin(form -> form.disable())
    //         .logout(logout -> logout
    //             .logoutUrl("/api/logout")
    //             .logoutSuccessUrl("/api/")
    //             .invalidateHttpSession(true)
    //             .deleteCookies("JSESSIONID")
    //             .permitAll()
    //         )
    //         .exceptionHandling(ex -> ex
    //             .authenticationEntryPoint((request, response, authException) -> {
    //                 response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Unauthorized");
    //             })
    //         );

    //     return http.build();
    // }


    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
            .csrf(csrf -> csrf
                .ignoringRequestMatchers("/api/login", "/api/logout")
                .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
            )
            .cors(cors -> cors.configurationSource(corsConfigurationSource()))
            .sessionManagement(session -> session
                .sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED)
                .maximumSessions(1)
                .maxSessionsPreventsLogin(false)
            )
            // Ensure SecurityContext is persisted (default behavior, explicitly confirming)
            .securityContext().requireExplicitSave(false) // Default in Spring Boot 3.x
            .and()
            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/api/login", "/api/", "/api/home").permitAll()
                .requestMatchers(org.springframework.http.HttpMethod.OPTIONS, "/**").permitAll()
                .requestMatchers("/api/client_home", "/api/client_view_tickets", "/api/client_obtain_ticket").hasAuthority("CLIENT")
                .requestMatchers("/api/agent_home").hasAuthority("AGENT")
                .requestMatchers("/api/admin").hasAuthority("ADMIN")
                .anyRequest().authenticated()
            )
            .formLogin(form -> form.disable())
            .logout(logout -> logout
                .logoutUrl("/api/logout")
                .logoutSuccessUrl("/api/")
                .invalidateHttpSession(true)
                .deleteCookies("JSESSIONID")
                .permitAll()
            )
            .exceptionHandling(ex -> ex
                .authenticationEntryPoint((request, response, authException) -> {
                    response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Unauthorized");
                })
            );

        return http.build();
    }

    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();
        configuration.setAllowedOrigins(Arrays.asList("https://okgestionfile-react-springboot-fullstack.onrender.com"));
        configuration.setAllowedMethods(Arrays.asList("GET", "POST", "PUT", "DELETE", "OPTIONS"));
        configuration.setAllowedHeaders(Arrays.asList("*"));
        configuration.setAllowCredentials(true);
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }
}