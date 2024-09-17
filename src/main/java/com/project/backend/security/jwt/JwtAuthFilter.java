package com.project.backend.security.jwt;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import com.project.backend.constants.TokenType;
import com.project.backend.dto.CustomOAuth2User;
import com.project.backend.dto.UserDTO;
import com.project.backend.security.service.UserDetailsServiceImpl;

import io.jsonwebtoken.ExpiredJwtException;

import java.io.IOException;
import java.io.PrintWriter;

@Slf4j
@Component
public class JwtAuthFilter extends OncePerRequestFilter {

    @Autowired
    private JwtUtils jwtUtils;

    @Autowired
    private UserDetailsServiceImpl userDetailsService;

    private static final Logger logger = LoggerFactory.getLogger(JwtAuthFilter.class);

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        logger.debug("AuthTokenFilter called for URI: {}", request.getRequestURI());

        String requestUri = request.getRequestURI();

        

        if (requestUri.matches("/api/auth/public/signin(?:\\/.*)?$")) {

            filterChain.doFilter(request, response);
            return;
        }

        if (requestUri.matches("^\\/oauth2(?:\\/.*)?$")) {

            filterChain.doFilter(request, response);
            return;
        }

       

        String oauth2 = null;
        Cookie[] cookies = request.getCookies();

        if (null != cookies) {
            for (Cookie cookie : cookies) {

                System.out.println(cookie.getName());
                if (cookie.getName().equals(TokenType.OAUTH2.getType())) {

                    oauth2 = cookie.getValue();
                }
            }
        }

        String accessToken = parseJwt(request);

        

        // 1 OAUTH 2 JWT
        if (oauth2 != null && accessToken == null) {

            String token = oauth2;

            if (jwtUtils.isJwtTokenExpired(token)) {

                System.out.println("token expired");
                filterChain.doFilter(request, response);

                // 조건이 해당되면 메소드 종료 (필수)
                return;
            }
            String id = jwtUtils.getIdFromJwtToken(token);
            String role = jwtUtils.getRoleFromJwtToken(token);

            UserDTO userDTO = new UserDTO();
            userDTO.setUsername(id);
            userDTO.setRole(role);

            CustomOAuth2User customOAuth2User = new CustomOAuth2User(userDTO);
            UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(customOAuth2User, null,
                customOAuth2User.getAuthorities());

            SecurityContextHolder.getContext().setAuthentication(authToken);

        }
        // 2. NORMAL JWT
        else if (oauth2 == null && accessToken != null) {

            

            try {
                jwtUtils.isJwtTokenExpired(accessToken);
            } catch (ExpiredJwtException e) {
                PrintWriter writer = response.getWriter();
                writer.print("access token expired");

                // response status code
                response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                return;
            }

            try {

                if (jwtUtils.validateJwtToken(accessToken)) {
                    String email = jwtUtils.getIdFromJwtToken(accessToken);

                    

                    UserDetails userDetails = userDetailsService.loadUserByUsername(email);

                    UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(
                            userDetails,
                            null,
                            userDetails.getAuthorities());
                    logger.debug("Roles from JWT: {}", userDetails.getAuthorities());

                    authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

                    SecurityContextHolder.getContext().setAuthentication(authentication);
                }
            } catch (Exception e) {
                // logger.error("Cannot set user authentication: {}", e);
                // response body
                PrintWriter writer = response.getWriter();
                writer.print("invalid access token");

                // response status code
                response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                return;
            }

        } else // 토큰이 없다면 다음 필터로 넘김
        if (oauth2 == null && accessToken == null) {

            

            filterChain.doFilter(request, response);

            return;
        }

        filterChain.doFilter(request, response);
    }

    private String parseJwt(HttpServletRequest request) {
        String jwt = jwtUtils.getJwtFromHeader(request);
        // String jwt = jwtUtils.getJwtFromCookies(request);
        logger.debug("AuthTokenFilter.java: {}", jwt);
        return jwt;
    }
}
