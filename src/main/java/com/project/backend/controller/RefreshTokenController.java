package com.project.backend.controller;

import java.text.SimpleDateFormat;
import java.util.Date;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.project.backend.constants.StatusMessages;
import com.project.backend.constants.TokenType;
import com.project.backend.exceptionHandling.TokenRefreshException;
import com.project.backend.model.RefreshToken;
import com.project.backend.model.User;

import com.project.backend.security.jwt.JwtUtils;
import com.project.backend.security.response.MessageResponse;
import com.project.backend.service.RefreshTokenService;
import com.project.backend.service.impl.UserServiceImpl;

import io.jsonwebtoken.ExpiredJwtException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@RestController
@RequestMapping("api/")
public class RefreshTokenController {

    private final UserServiceImpl userService;

    private final JwtUtils jwtUtils;

    private final RefreshTokenService refreshTokenService;

    @Autowired
    public RefreshTokenController(UserServiceImpl userService, JwtUtils jwtUtils, RefreshTokenService refreshTokenService) {
        this.userService = userService;
        this.jwtUtils = jwtUtils;
        this.refreshTokenService = refreshTokenService;
    }

    @PostMapping("/token/refresh")
    public ResponseEntity<?> refreshtoken(HttpServletRequest request, HttpServletResponse response) {
        
        String refresh = null;
        Cookie[] cookies = request.getCookies();
        for (Cookie cookie : cookies) {

            if (cookie.getName().equals(TokenType.REFRESH.getType())) {

                refresh = cookie.getValue();

                
            }
        }
        
        if (refresh == null) {

            
            //response status code
            return new ResponseEntity<>("refresh token null", HttpStatus.BAD_REQUEST);
        }

         //expired check
        try {
            jwtUtils.isJwtTokenExpired(refresh);
        } catch (ExpiredJwtException e) {

            //로그인 페이지 
            //response status code

            return new ResponseEntity<>("refresh token expired", HttpStatus.BAD_REQUEST);
        }

        
        if(!jwtUtils.validateJwtToken(refresh)) {

            
            //response status code
            return new ResponseEntity<>("invalid refresh token", HttpStatus.BAD_REQUEST);
        }

        if(!refreshTokenService.findByToken(refresh).isPresent())  {
                //response body
            
             throw new TokenRefreshException(refresh,
                               "Refresh token is not in database!");
        }


        String email = jwtUtils.getIdFromJwtToken(refresh);

        User user = userService.findByEmail(email).
                    orElseThrow(() -> new RuntimeException("User not found with email: " + email));       

        String newAccess = jwtUtils.generateTokenFromUser(user);

        // delete and create         
        RefreshToken refreshToken = refreshTokenService.createRefreshToken(user.getUserId());

        log.info("토큰 재발급 성공");

        response.setHeader(TokenType.ACCESS.getType(), newAccess);
        response.addCookie(jwtUtils.createCookie(TokenType.REFRESH.getType(), refreshToken.getToken(), 24*60*60));
        //response.setHeader(HttpHeaders.SET_COOKIE, jwtUtils.generateRefreshJwtCookie(refreshToken.getToken()).toString());

        return new ResponseEntity<>(HttpStatus.OK);        
    }

    // @PostMapping("/token/delete")
    // public ResponseEntity<?> delete(HttpServletRequest request, HttpServletResponse response, 
    // @AuthenticationPrincipal UserDetails userDetails) {

    //     if (null != userDetails ) {
        
    //       Cookie cookie = jwtUtils.createCookie(TokenType.REFRESH.getType(), null, 0);

    //       response.addCookie(cookie);
          
    //       return new ResponseEntity<>(HttpStatus.OK);   
    //     }
    //     else {                    
    //         return ResponseEntity.status(HttpStatus.NOT_FOUND)
    //                 .body(StatusMessages.USER_NOT_FOUND);
    //     }            

    // }


}
