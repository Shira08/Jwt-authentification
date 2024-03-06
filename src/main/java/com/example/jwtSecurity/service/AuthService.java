package com.example.jwtSecurity.service;

import com.example.jwtSecurity.entity.Role;
import com.example.jwtSecurity.entity.User;
import com.example.jwtSecurity.payload.AuthenticationRequest;
import com.example.jwtSecurity.payload.AuthenticationResponse;
import com.example.jwtSecurity.payload.RegisterRequest;
import com.example.jwtSecurity.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class AuthService {

    private static UserRepository userRepository;
    private static PasswordEncoder passwordEncoder;
    private static JwtService jwtService;

    private static AuthenticationManager authenticationManager;

    public AuthService(PasswordEncoder passwordEncoder, JwtService jwtService) {
        this.passwordEncoder = passwordEncoder;
        this.jwtService = jwtService;
    }

    public static AuthenticationResponse register(RegisterRequest request) {
        /*var user = User.builder()
                .firstname(request.getFirstname())
                .lastname(request.getLastname())
                .email(request.getEmail())
                .password(passwordEncoder.encode(request.getPassword()))
                .role(Role.USER)
                .build();
        userRepository.save(user);
        var jwtToken = jwtService.generateToken(user);
        return AuthenticationResponse.builder()
                .token(jwtToken)
                .build();*/
        var user = new User();
        user.setFirstname(request.getFirstname());
        user.setLastname(request.getLastname());
        user.setEmail(request.getEmail());
        user.setPassword(passwordEncoder.encode(request.getPassword()));
        user.setRole(Role.USER);

        userRepository.save(user);

        String jwtToken = jwtService.generateToken(user);

        AuthenticationResponse authenticationResponse = new AuthenticationResponse();
        authenticationResponse.setToken(jwtToken);

        return authenticationResponse;

    }

    public static AuthenticationResponse authenticate(AuthenticationRequest request)
    {
        authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(
                request.getEmail(),
                request .getPassword()
        ));
        User user = userRepository.findByEmail(request.getEmail()).orElseThrow();
       var jwtToken = jwtService.generateToken(user);
        AuthenticationResponse authenticationResponse = new AuthenticationResponse();
        authenticationResponse.setToken(jwtToken);

        return authenticationResponse;
    }
}
