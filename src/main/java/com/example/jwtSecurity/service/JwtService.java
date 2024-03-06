package com.example.jwtSecurity.service;

import com.example.jwtSecurity.entity.User;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.security.Key;
import java.util.Base64;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;


@Service
public class JwtService {
    //validation process
    final String secretKey = "JhFZcGAr8BFaDMz92EslI2LOuUUjnji4";

    //check if the username in the token is same as the one the user sent (userDetails)
    public boolean isTokenValid(String token, UserDetails userDetails)
    {
        final String username = extractUsername(token);
        return (username.equals(userDetails.getUsername())) && !isTokenExpired(token);
    }

    private boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }

    private Date extractExpiration(String token) {
        return extractClaim(token,Claims::getExpiration);
    }

    public String extractUsername(String token)
    {
        //use single claims extract to username
        return extractClaim(token, Claims::getSubject);
    }
    public String generateToken(
            UserDetails userDetails)
    {
        return generateToken(new HashMap <> (), userDetails);
    }
    public String generateToken(
            Map <String,Object> extraClaims,
            UserDetails userDetails
                                )
    {
        return Jwts
                .builder()
                .setClaims(extraClaims)
                //get it from the information the user type
                .setSubject(userDetails.getUsername())
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + 1000 * 60 * 24))
                //using the method getSignInKey we created
                .signWith(getSignInKey() , SignatureAlgorithm.HS256)
                .compact() ;// compact will generate and return the token
    }
    //extract single claims
    public <T> T extractClaim(String token, Function<Claims,T> claimsResolver)
    {
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }
    private Claims extractAllClaims(String token)
    {
        return Jwts
                .parserBuilder()
                //use to create the signature part of the token
                //ensure that the user who is sending the jwt is the one who is sending th request
                //
                .setSigningKey(getSignInKey())
                .build()
                .parseClaimsJws(token)
                .getBody();

    }

    private Key getSignInKey() {
        byte[] keyBytes = Decoders.BASE64.decode(secretKey);

        return Keys.hmacShaKeyFor(keyBytes);
    }
}
