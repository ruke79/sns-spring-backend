package com.project.backend.controller;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.project.backend.constants.StatusMessages;

import com.project.backend.dto.UserDTO;
import com.project.backend.model.User;
import com.project.backend.security.request.PasswordRequest;
import com.project.backend.security.response.MessageResponse;
import com.project.backend.security.service.UserDetailsImpl;

import com.project.backend.service.impl.UserServiceImpl;

@RestController
@RequestMapping("/api/user/profile")
public class UserController {

    private final UserServiceImpl userService;


    @Autowired
    public UserController(UserServiceImpl userService) {
                this.userService = userService;
        
    }

    
    @GetMapping("/payment")
    ResponseEntity<?> getUserInfoWithPayment(@AuthenticationPrincipal UserDetails userDetails) {

        if (null != userDetails) {

            try {

                User user = userService.findByUsername(userDetails.getUsername());

                UserDTO repsonse = userService.findUserWithdefaultPaymentMethod(user);

                return new ResponseEntity<>(repsonse, HttpStatus.OK);
            } catch (RuntimeException e) {
                return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                        .body(new MessageResponse(StatusMessages.GET_USERINFO_FAILED));
            }
        } else {
            return ResponseEntity.status(HttpStatus.NOT_FOUND)
                    .body(StatusMessages.USER_NOT_FOUND);
        }

    }

    
    @PutMapping("/update-password")
    public ResponseEntity<String> updatePassword(@RequestBody PasswordRequest request,
            @AuthenticationPrincipal UserDetails userDetails) {

    if (null != userDetails) {
        try {
            UserDetailsImpl user =(UserDetailsImpl)userDetails;
            userService.updatePassword(user.getId(), request.getCurrent_password(), request.getNew_password());
            return ResponseEntity.ok("Password updated");
        } catch (RuntimeException e) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(e.getMessage());
        }
    }
    else {
        return ResponseEntity.status(HttpStatus.NOT_FOUND)
                .body(StatusMessages.USER_NOT_FOUND);
    }
}

}
