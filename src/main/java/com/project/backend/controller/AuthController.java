package com.project.backend.controller;


import com.project.backend.constants.StatusMessages;
import com.project.backend.model.User;

import com.project.backend.repository.RoleRepository;
import com.project.backend.repository.UserRepository;

import com.project.backend.security.jwt.JwtUtils;

import com.project.backend.security.request.SignupRequest;
import com.project.backend.security.response.GenericResponse;

import com.project.backend.security.response.MessageResponse;
import com.project.backend.security.response.UserInfoResponse;
import com.project.backend.service.TotpService;
import com.project.backend.service.UserService;
import com.project.backend.util.AuthUtil;
import com.warrenstrange.googleauth.GoogleAuthenticatorKey;



import jakarta.servlet.http.HttpServletRequest;

import jakarta.validation.Valid;



import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.http.HttpStatus;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    
    private final JwtUtils jwtUtils;

    
    private final  ApplicationEventPublisher eventPublisher;

    
    private final UserRepository userRepository;

    
    //private final RoleRepository roleRepository;

    private final UserService userService;

    
    private final AuthUtil authUtil;

    
    private final TotpService totpService;

            
    @Autowired
    public AuthController(JwtUtils jwtUtils, 
            ApplicationEventPublisher eventPublisher, UserRepository userRepository, 
            UserService userService, AuthUtil authUtil, TotpService totpService
            ) {
        this.jwtUtils = jwtUtils;
        
        this.eventPublisher = eventPublisher;
        this.userRepository = userRepository;        
        this.userService = userService;
        this.authUtil = authUtil;
        this.totpService = totpService;        
    }

  
    @PostMapping("/public/signup")
    public ResponseEntity<?> registerUser(@Valid @RequestBody SignupRequest signUpRequest) {
       
       
        if (userRepository.existsByUserName(signUpRequest.getUsername())) {
            return ResponseEntity.badRequest().body(new MessageResponse(StatusMessages.USERNAME_IN_USE));
        }

        if (userRepository.existsByEmail(signUpRequest.getEmail())) {
            return ResponseEntity.badRequest().body(new MessageResponse(StatusMessages.EMAIL_IN_USE));
        }

        userService.registerNewUserAccount(signUpRequest);

        return ResponseEntity.ok(new MessageResponse(StatusMessages.USER_REGISTRATION_SUCCESS));
    }

    // Email Vertification
    @PostMapping("/public/register")
    public ResponseEntity<?> registerUserAccount(@Valid @RequestBody SignupRequest accountDto,
            final HttpServletRequest request) {

                try {

            final User registered = userService.registerNewUserAccount(accountDto);
            // userService.addUserLocation(registered, getClientIP(request));

            eventPublisher.publishEvent(new com.project.backend.registration.OnRegistrationCompleteEvent(registered,
                    request.getLocale(), getAppUrl(request)));
            return new ResponseEntity<>(new GenericResponse(StatusMessages.USER_REGISTRATION_SUCCESS), HttpStatus.OK);
                }
                catch(RuntimeException e) {

                    return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body("User Resigtration failed");
                }
    }
    

    @GetMapping("/user")
    public ResponseEntity<?> getUserDetails(@AuthenticationPrincipal UserDetails userDetails) {
        User user = userService.findByUsername(userDetails.getUsername());

        if (null != user) {

            List<String> roles = userDetails.getAuthorities().stream()
                    .map(item -> item.getAuthority())
                    .collect(Collectors.toList());

            UserInfoResponse response = new UserInfoResponse(
                    user.getUserId(),
                    user.getUserName(),
                    user.getEmail(),
                    user.getImage(),
                    user.isAccountNonLocked(),
                    user.isAccountNonExpired(),
                    user.isCredentialsNonExpired(),
                    user.isEnabled(),
                    user.getCredentialsExpiryDate(),
                    user.getAccountExpiryDate(),
                    user.isTwoFactorEnabled(),
                    roles);

            return ResponseEntity.ok().body(response);
        }
        else 
            {
                return ResponseEntity.status(HttpStatus.NOT_FOUND)
                    .body(StatusMessages.USER_NOT_FOUND);
            }
    }

    @GetMapping("/username")
    public String currentUserName(@AuthenticationPrincipal UserDetails userDetails) {
        return (userDetails != null) ? userDetails.getUsername() : "";
    }

    @PostMapping("/public/forgot-password")
    public ResponseEntity<?> forgotPassword(@RequestParam String email) {
        try {
            userService.generatePasswordResetToken(email);
            return ResponseEntity.ok(new MessageResponse("Password reset email sent!"));
        } catch (Exception e) {
            e.printStackTrace();
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(new MessageResponse("Error sending password reset email"));
        }

    }

    @PostMapping("/public/reset-password")
    public ResponseEntity<?> resetPassword(@RequestParam String token,
            @RequestParam String newPassword) {

        try {
            userService.resetPassword(token, newPassword);
            return ResponseEntity.ok(new MessageResponse("Password reset successful"));
        } catch (RuntimeException e) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body(new MessageResponse(e.getMessage()));
        }
    }

    // 2FA Authentication
    @PostMapping("/enable-2fa")
    public ResponseEntity<String> enable2FA() {
        Long userId = authUtil.loggedInUserId();
        GoogleAuthenticatorKey secret = userService.generate2FASecret(userId);
        String qrCodeUrl = totpService.getQrCodeUrl(secret,
                userService.getUserById(userId).getUsername());
        return ResponseEntity.ok(qrCodeUrl);
    }

    @PostMapping("/disable-2fa")
    public ResponseEntity<String> disable2FA() {
        Long userId = authUtil.loggedInUserId();
        userService.disable2FA(userId);
        return ResponseEntity.ok("2FA disabled");
    }

    @PostMapping("/verify-2fa")
    public ResponseEntity<String> verify2FA(@RequestParam int code) {
        Long userId = authUtil.loggedInUserId();
        boolean isValid = userService.validate2FACode(userId, code);
        if (isValid) {
            userService.enable2FA(userId);
            return ResponseEntity.ok("2FA Verified");
        } else {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body("Invalid 2FA Code");
        }
    }

    @GetMapping("/user/2fa-status")
    public ResponseEntity<?> get2FAStatus() {
        User user = authUtil.loggedInUser();
        if (user != null) {
            return ResponseEntity.ok().body(Map.of("is2faEnabled", user.isTwoFactorEnabled()));
        } else {
            return ResponseEntity.status(HttpStatus.NOT_FOUND)
                    .body(StatusMessages.USER_NOT_FOUND);
        }
    }

    @PostMapping("/public/verify-2fa-login")
    public ResponseEntity<String> verify2FALogin(@RequestParam int code,
            @RequestParam String jwtToken) {
        String username = jwtUtils.getIdFromJwtToken(jwtToken);
        User user = userService.findByUsername(username);
        boolean isValid = userService.validate2FACode(user.getUserId(), code);
        if (isValid) {
            return ResponseEntity.ok("2FA Verified");
        } else {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body("Invalid 2FA Code");
        }
    }

    private String getAppUrl(HttpServletRequest request) {
        return "http://" + request.getServerName() + ":" + request.getServerPort() + request.getContextPath();
    }

    private String getClientIP(HttpServletRequest request) {
        final String xfHeader = request.getHeader("X-Forwarded-For");
        if (xfHeader == null || xfHeader.isEmpty() || !xfHeader.contains(request.getRemoteAddr())) {
            return request.getRemoteAddr();
        }
        return xfHeader.split(",")[0];
    }

   


    

}