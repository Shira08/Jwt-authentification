package com.example.jwtSecurity.controller;

import com.example.jwtSecurity.payload.AuthenticationRequest;
import com.example.jwtSecurity.payload.AuthenticationResponse;
import com.example.jwtSecurity.payload.RegisterRequest;
import com.example.jwtSecurity.service.AuthService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
public class AuthController {
    @PostMapping("/register")
    public ResponseEntity<AuthenticationResponse> register(@RequestBody RegisterRequest request)
    {
        return ResponseEntity.ok(AuthService.register(request));
    }
    @PostMapping("/authenticate")
    public ResponseEntity<AuthenticationResponse> authenticate(@RequestBody AuthenticationRequest request)
    {
        return ResponseEntity.ok(AuthService.authenticate(request));
    }
}
