package com.example.jwtSecurity.config;


import jakarta.servlet.Filter;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.Customizer;
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

    private JwtAuthenticationFilter jwtAuthFilter;
    private final AuthenticationProvider authenticationProvider;

    public SecurityConfiguration(AuthenticationProvider authenticationProvider) {
        this.authenticationProvider = authenticationProvider;
    }

    // securityfilterchain is the bean responsible
    // of configuring all the http security of the app
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .csrf(AbstractHttpConfigurer::disable)
                .authorizeRequests(authorize -> authorize
                        .requestMatchers("/api/v1/auth/**").permitAll()
                        //.requestMatchers("").hasAuthority("employee:read")
                        // .requestMatchers(HttpMethod.GET, "/users/**").hasAnyAuthority("ROLE_ADMIN_READ", "ROLE_USER_READ")
                        .anyRequest().authenticated()
                )
                .sessionManagement(sessions -> sessions
                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                )
                .authenticationProvider(authenticationProvider)
                .addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter.class)
                // Note: The comment about not saving the state to ensure each user is authenticated before each request
                // is implied by the sessionCreationPolicy(SessionCreationPolicy.STATELESS) setting.
                .httpBasic(Customizer.withDefaults());
        return http.build();
    }

}
