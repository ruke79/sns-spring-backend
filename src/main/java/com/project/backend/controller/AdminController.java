package com.project.backend.controller;

import org.hibernate.mapping.Set;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import com.project.backend.constants.StatusMessages;
import com.project.backend.dto.UserDTO;
import com.project.backend.model.Role;
import com.project.backend.model.User;
import com.project.backend.security.request.ImageRequest;



import com.project.backend.security.response.GenericResponse;
import com.project.backend.security.response.MessageResponse;

import com.project.backend.service.UserService;

import jakarta.mail.Multipart;
import lombok.extern.java.Log;
import lombok.extern.slf4j.Slf4j;

import java.io.IOException;
import java.io.ObjectInputFilter.Status;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

@Slf4j
@RestController
@RequestMapping("/api/admin")
// @PreAuthorize("hasRole('ROLE_ADMIN')")
public class AdminController {

    private final UserService userService;

    
    public AdminController(UserService userService) {
        this.userService = userService;
    }


    @GetMapping("/getusers")
    public ResponseEntity<List<User>> getAllUsers() {
        return new ResponseEntity<>(userService.getAllUsers(),
                HttpStatus.OK);
    }

    @PutMapping("/update-role")
    public ResponseEntity<String> updateUserRole(@RequestParam Long userId,
            @RequestParam String roleName) {
        userService.updateUserRole(userId, roleName);
        return ResponseEntity.ok(StatusMessages.USER_ROLE_UPDATED);
    }

    @GetMapping("/user/{id}")
    public ResponseEntity<UserDTO> getUser(@PathVariable Long id) {
        return new ResponseEntity<>(userService.getUserById(id),
                HttpStatus.OK);
    }

    @PutMapping("/update-lock-status")
    public ResponseEntity<String> updateAccountLockStatus(@RequestParam Long userId,
            @RequestParam boolean lock) {
        userService.updateAccountLockStatus(userId, lock);
        return ResponseEntity.ok(StatusMessages.ACCOUNT_LOCK_STATUS_UPDATED);
    }

    @GetMapping("/roles")
    List<Role> getAllRoles() {
        return userService.getAllRoles();
    }

    @PutMapping("/update-expiry-status")
    ResponseEntity<String> updateAccountExpiryStatus(@RequestParam Long userId,
            @RequestParam boolean expire) {
        userService.updateAccountExpiryStatus(userId, expire);
        return ResponseEntity.ok(StatusMessages.ACCOUNT_EXPIRY_STATUS_UPDATED);
    }

    @PutMapping("/update-enabled-status")
    ResponseEntity<String> updateAccountEnabledStatus(@RequestParam Long userId,
            @RequestParam boolean enabled) {
        userService.updateAccountEnabledStatus(userId, enabled);
        return ResponseEntity.ok(StatusMessages.ACCOUNT_ENABLE_STATUS_UPDATED);
    }

    @PutMapping("/update-credentials-expiry-status")
    ResponseEntity<String> updateCredentialsExpiryStatus(@RequestParam Long userId,
            @RequestParam boolean expire) {
        userService.updateCredentialsExpiryStatus(userId, expire);
        return ResponseEntity.ok(StatusMessages.CREDENTIALS_EXPIRY_STATUS_UPDATED);
    }

    @PutMapping("/update-password")
    ResponseEntity<String> updatePassword(@RequestParam Long userId,
            @RequestParam String password) {
        try {
            userService.updatePassword(userId, password);
            return ResponseEntity.ok(StatusMessages.PASSWORD_UPDATED);
        } catch (RuntimeException e) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(e.getMessage());
        }
    }    

}
