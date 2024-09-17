package com.project.backend.security;

import java.io.IOException;
import java.io.PrintWriter;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.filter.GenericFilterBean;

import com.project.backend.constants.TokenType;
import com.project.backend.model.RefreshToken;
import com.project.backend.model.User;
import com.project.backend.security.jwt.JwtUtils;
import com.project.backend.service.RefreshTokenService;
import com.project.backend.service.UserService;

import ch.qos.logback.core.subst.Token;
import io.jsonwebtoken.ExpiredJwtException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;

@Slf4j
public class AuthLogoutFilter extends GenericFilterBean{
    
    
    private final JwtUtils jwtUtils;
    
    private final RefreshTokenService refreshTokenService;
    
    private final UserService userService;
    
    @Autowired
    public AuthLogoutFilter(JwtUtils jwtUtils, RefreshTokenService refreshTokenService, UserService userService) {
        this.jwtUtils = jwtUtils;
        this.refreshTokenService = refreshTokenService;
        this.userService = userService;
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        // TODO Auto-generated method stub

        doFilter((HttpServletRequest) request, (HttpServletResponse) response, chain);
        
    }

     private void doFilter(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws IOException, ServletException {

     
        //path and method verify
        String requestUri = request.getRequestURI();
        if (!requestUri.matches("/api/auth/logout$")) {

            filterChain.doFilter(request, response);
            return;
        }
        
        String requestMethod = request.getMethod();
        if (!requestMethod.equals("POST")) {

            filterChain.doFilter(request, response);
            return;
        }
        
        //get refresh token
        String refresh = null;
        Cookie[] cookies = request.getCookies();
        for (Cookie cookie : cookies) {

            if (cookie.getName().equals(TokenType.REFRESH.getType())) {

                refresh = cookie.getValue();
            }
        }

        //refresh null check
        if (refresh == null) {

            PrintWriter writer = response.getWriter();
                writer.print("refresh cookie not found");

            response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
            return;
        }

        //expired check
        try {
            jwtUtils.isJwtTokenExpired(refresh);
        } catch (ExpiredJwtException e) {

            PrintWriter writer = response.getWriter();
                writer.print("refresh token expired");
            //response status code
            response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
            return;
        }

        if(!jwtUtils.validateJwtToken(refresh)) {

            PrintWriter writer = response.getWriter();
                writer.print("refresh token invalid");

            //response status code
            response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
            return;
        }
        

        //DB에 저장되어 있는지 확인
        if(!refreshTokenService.findByToken(refresh).isPresent())  {

            PrintWriter writer = response.getWriter();
                writer.print("refresh token not found");

            //response status code
            response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
            return;
        }

        //로그아웃 진행
        //Refresh 토큰 DB에서 제거
        String email = jwtUtils.getIdFromJwtToken(refresh);
        User user = userService.findByEmail(email).
                    orElseThrow(() -> new RuntimeException("User not found with email: " + email));       
       
        refreshTokenService.deleteByUserId(user.getUserId());

        //Refresh 토큰 Cookie 값 0
        Cookie cookie = new Cookie(TokenType.REFRESH.getType(), null);
        cookie.setMaxAge(0);
        cookie.setPath("/");

        response.addCookie(cookie);
        response.setStatus(HttpServletResponse.SC_OK);

        log.info("Logout Success");
    }    

}
