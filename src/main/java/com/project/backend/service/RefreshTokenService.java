package com.project.backend.service;

import java.text.SimpleDateFormat;
import java.time.Instant;
import java.time.LocalDateTime;
import java.util.Date;
import java.util.Optional;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.project.backend.constants.StatusMessages;
import com.project.backend.exceptionHandling.TokenRefreshException;
import com.project.backend.model.RefreshToken;
import com.project.backend.model.User;
import com.project.backend.repository.RefreshTokenRepository;
import com.project.backend.repository.UserRepository;
import com.project.backend.security.jwt.JwtUtils;

import lombok.extern.slf4j.Slf4j;

@Slf4j
@Service
public class RefreshTokenService {

  @Value("${spring.app.jwtRefreshExpirationMs}")
  private Long refreshTokenDurationMs;

    
  private final RefreshTokenRepository refreshTokenRepository;
  
  
  private final UserRepository userRepository;

  private final JwtUtils jwtUtils;

  
  @Autowired
  public RefreshTokenService(RefreshTokenRepository refreshTokenRepository, UserRepository userRepository,
      JwtUtils jwtUtils) {
    this.refreshTokenRepository = refreshTokenRepository;
    this.userRepository = userRepository;
    this.jwtUtils = jwtUtils;
  }

  public Optional<RefreshToken> findByToken(String token) {
    return refreshTokenRepository.findByToken(token);
  }

  public RefreshToken createRefreshToken(Long userId) {
    RefreshToken refreshToken = new RefreshToken();

    User user = userRepository.findById(userId)
    .orElseThrow(() -> new RuntimeException(StatusMessages.USER_NOT_FOUND));

    

    refreshTokenRepository.deleteByUser(user);


    refreshToken.setUser(user);    
    
    refreshToken.setToken(jwtUtils.generatRefreshTokenFromUser(user));
   
    Date myDate = Date.from(Instant.now().plusMillis(refreshTokenDurationMs));
      
    refreshToken.setExpiryDate(myDate);


    refreshToken = refreshTokenRepository.save(refreshToken);
    return refreshToken;
  }



  @Transactional  
  public int deleteByUserId(Long userId) {
    User user = userRepository.findById(userId)
    .orElseThrow(() -> new RuntimeException(StatusMessages.USER_NOT_FOUND));
    return refreshTokenRepository.deleteByUser(user)
    ;
  }

}
