package com.example.jwtSecurity.config;

import com.example.jwtSecurity.service.JwtService;
import com.nimbusds.oauth2.sdk.Request;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;


import java.io.IOException;

@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {
    private final JwtService jwtService;
    private final UserDetailsService userDetailsService;

    public JwtAuthenticationFilter(JwtService jwtService, UserDetailsService userDetailsService) {
        this.jwtService = jwtService;
        this.userDetailsService = userDetailsService;
    }

    @Override
    protected void doFilterInternal(
            @NonNull HttpServletRequest request,
            @NonNull HttpServletResponse response,
            @NonNull FilterChain filterChain) throws ServletException, IOException {

        //retrieve authHeader and check if it null or not start with Bearer
        final String authHeader = request.getHeader("Authorization");
        final String jwt;
        final String userEmail;

        if(authHeader == null || !authHeader.startsWith("Bearer "))
        {
            filterChain.doFilter(request , response);
            return;
        }
        //get string starting by index xx
        jwt = authHeader.substring(7);
        userEmail = jwtService.extractUsername(jwt);
        //check if user is already authenticated
        if (userEmail != null && SecurityContextHolder.getContext().getAuthentication() == null)
        {
            //user not authenticated
            //applicationConfig
            UserDetails userDetails = this.userDetailsService.loadUserByUsername(userEmail);
            //token valid?
            if(jwtService.isTokenValid(jwt,userDetails))
            {
                //represent the authenticated user , use to manage the user's authentication state
                UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
                        userDetails,
                        //he second argument is the credentials (which are set to null since the authentication was done using a token)
                        null,
                        userDetails.getAuthorities()
                );
                //WebAuthenticationDetailsSource creates a WebAuthenticationDetails
                // object, which includes details such as the IP address of the client
                // and the session ID, if any. This information can be useful for auditing
                // or additional security checks
                authToken.setDetails(
                        new WebAuthenticationDetailsSource().buildDetails(request)
                );
                // set the securityConfigHolder ; the authentication token is set in
                // the SecurityContextHolder. The SecurityContextHolder is a holder
                // class that provides access to the security context. The security
                // context is where Spring Security stores details about the currently
                // authenticated user. Setting the authentication in the context makes
                // the user authenticated for the duration of their session, allowing them to access secured resources
                SecurityContextHolder.getContext().setAuthentication(authToken);
            }
        }
        filterChain.doFilter(request,response);
    }
}
