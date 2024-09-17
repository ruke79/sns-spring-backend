package com.project.backend.security.jwt;

import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.stream.Collectors;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.ResponseCookie;
import org.springframework.stereotype.Component;
import org.springframework.web.util.WebUtils;

import com.project.backend.model.User;
import com.project.backend.security.service.UserDetailsImpl;

import io.jsonwebtoken.*;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import jakarta.annotation.PostConstruct;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;


@Slf4j
@Component
public class JwtUtils {
  private static final Logger logger = LoggerFactory.getLogger(JwtUtils.class);

  
  
  @Value("${spring.app.jwtSecret}")
  private String jwtSecret;

  @Value("${spring.app.jwtExpirationMs}")
  private int jwtExpirationMs;

  @Value("${spring.app.jwtRefreshExpirationMs}")
  private int jwtRefreshExpirationMs;

  @Value("${spring.app.jwtCookieName}")
  private String jwtCookie;

  @Value("${spring.app.jwtRefreshCookieName}")
  private  String jwtRefreshCookie;

  

  
  private SecretKey key() {
    return new SecretKeySpec(jwtSecret.getBytes(StandardCharsets.UTF_8),
    Jwts.SIG.HS256.key().build().getAlgorithm());
}
  


  public String getJwtFromHeader(HttpServletRequest request) {
    String bearerToken = request.getHeader("Authorization");
    logger.debug("Authorization Header: {}", bearerToken);
    if (bearerToken != null && bearerToken.startsWith("Bearer ")) {
      return bearerToken.substring(7); // Remove Bearer prefix
    }
    return null;
  }


  public String generateTokenFromUser(User user) {
    
    String email = user.getEmail();
    String role = user.getRole().getRoleName().name();
    return Jwts.builder()
        .subject(email)
        .claim("role", role)
        .claim("is2faEnabled", user.isTwoFactorEnabled())
        .issuedAt(new Date(System.currentTimeMillis()))
        .expiration(new Date(System.currentTimeMillis() + jwtExpirationMs))
        .signWith(key())
        .compact();
  }

  

  public String generatRefreshTokenFromUser(User user) {
    
    String email = user.getEmail();
    String role = user.getRole().getRoleName().name();
    return Jwts.builder()
        .subject(email)
        .claim("role", role)
        .claim("is2faEnabled", user.isTwoFactorEnabled())
        .issuedAt(new Date(System.currentTimeMillis()))
        .expiration(new Date(System.currentTimeMillis() + jwtRefreshExpirationMs))
        .signWith(key())
        .compact();
  }

  public String generateToken(String id, String role, boolean isTwoFactorEnabled, long expirationMs) {
    
    return Jwts.builder()
        .subject(id)
        .claim("role", role)
        .claim("is2faEnabled", isTwoFactorEnabled)
        .issuedAt(new Date(System.currentTimeMillis()))
        .expiration(new Date(System.currentTimeMillis() + expirationMs))
        .signWith(key())
        .compact();
  }

  public String generateToken(String id, String role, boolean isTwoFactorEnabled) {
    
    return Jwts.builder()
        .subject(id)
        .claim("role", role)
        .claim("is2faEnabled", isTwoFactorEnabled)
        .issuedAt(new Date(System.currentTimeMillis()))
        .expiration(new Date(System.currentTimeMillis() + jwtExpirationMs))
        .signWith(key())
        .compact();
  }

  public String getIdFromJwtToken(String token) {
    return Jwts.parser()
        .verifyWith(key())
        .build().parseSignedClaims(token)
        .getPayload().getSubject();
  }

  public String getRoleFromJwtToken(String token) {

    return Jwts.parser().verifyWith(key()).build().parseSignedClaims(token).getPayload().get("role", String.class);
  }
  

  public Boolean isJwtTokenExpired(String token) {
    return Jwts.parser()
        .verifyWith(key())
        .build().parseSignedClaims(token)
        .getPayload().getExpiration().before(new Date());
  }
 

  public boolean validateJwtToken(String authToken) {
    try {
      System.out.println("Validate");
      Jwts.parser().verifyWith(key())
          .build().parseSignedClaims(authToken);
      return true;
    } catch (MalformedJwtException e) {
      logger.error("Invalid JWT token: {}", e.getMessage());
    } catch (ExpiredJwtException e) {
      logger.error("JWT token is expired: {}", e.getMessage());
    } catch (UnsupportedJwtException e) {
      logger.error("JWT token is unsupported: {}", e.getMessage());
    } catch (IllegalArgumentException e) {
      logger.error("JWT claims string is empty: {}", e.getMessage());
    }
    return false;
  }

  // Http only cookie + JWT
  
  // public ResponseCookie generateJwtCookie(User user) {
  //   String jwt = generateTokenFromUser(user);
  //   return generateCookie(jwtCookie, jwt, "/api");
  // }

  // public ResponseCookie generateRefreshJwtCookie(String refreshToken) {
  //   return generateCookie(jwtRefreshCookie, refreshToken, "/");
  // }\ 

  // public ResponseCookie getCleanJwtCookie() {
  //   ResponseCookie cookie = ResponseCookie.from(jwtCookie, null).path("/api").build();
  //   return cookie;
  // }

  // public ResponseCookie getCleanJwtRefreshCookie() {
  //   ResponseCookie cookie = ResponseCookie.from(jwtRefreshCookie, null).path("/api").build();
  //   return cookie;
  // }

  // private ResponseCookie generateCookie(String name, String value, String path) {
  //   ResponseCookie cookie = ResponseCookie.from(name, value)
  //   .path(path).maxAge(24 * 60 * 60)
  //   .sameSite("None")    
  //   .secure(true)
  //   .httpOnly(true).build();
  //   return cookie;
  // }

  public Cookie createCookie(String key, String value, int expiry) {

    Cookie cookie = new Cookie(key, value);
    cookie.setMaxAge(expiry);
    cookie.setSecure(true);
    cookie.setPath("/");
    cookie.setHttpOnly(true);

    return cookie;
}

  private String getCookieValueByName(HttpServletRequest request, String name) {
    Cookie cookie = WebUtils.getCookie(request, name);
    if (cookie != null) {
      return cookie.getValue();
    } else {
      return null;
    }    
  }

  public String getJwtFromCookies(HttpServletRequest request) {
    return getCookieValueByName(request, jwtCookie);
  }

  public String getJwtRefreshFromCookies(HttpServletRequest request) {
    return getCookieValueByName(request, jwtRefreshCookie);
  }

}
