package com.springconcepts.security.util;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.util.Date;
import java.util.HashMap;
import java.util.Map;

@Service
public class JwtTokenUtil {

  @Value("${JWT_SECRET_KEY}")
  private String secretKey;

  public String extractUsername(String token) {
    return decodeToken(token).getSubject();
  }

  public Date extractExpiration(String token) {
    return decodeToken(token).getExpiresAt();
  }

  private DecodedJWT decodeToken(String token) {
    JWTVerifier verifier = JWT.require(Algorithm.HMAC256(secretKey)).build();
    return verifier.verify(token);
  }

  private Boolean isTokenExpired(String token) {
    return extractExpiration(token).before(new Date());
  }

  public String generateToken(UserDetails userDetails) {
    Map<String, Object> claims = new HashMap<>();
    return createToken(claims, userDetails.getUsername());
  }

  private String createToken(Map<String, Object> claims, String subject) {
    return JWT.create()
        .withSubject(subject)
        .withIssuedAt(new Date(System.currentTimeMillis()))
        .withExpiresAt(new Date(System.currentTimeMillis() + 1000 * 60 * 60 * 10))
        .withPayload(claims)
        .sign(Algorithm.HMAC256(secretKey));
  }

  public Boolean validateToken(String token, UserDetails userDetails) {
    final String username = extractUsername(token);
    return (username.equals(userDetails.getUsername()) && !isTokenExpired(token));
  }
}
