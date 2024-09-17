package com.project.backend.service;

import com.project.backend.dto.UserDTO;
import com.project.backend.model.Role;
import com.project.backend.model.User;
import com.project.backend.model.VerificationToken;
import com.project.backend.security.request.SignupRequest;
import com.warrenstrange.googleauth.GoogleAuthenticatorKey;

import java.util.List;
import java.util.Optional;

public interface UserService {
    void updateUserRole(Long userId, String roleName);

    List<User> getAllUsers();

    UserDTO getUserById(Long id);

    User findByUsername(String username);

    void updateAccountLockStatus(Long userId, boolean lock);

    List<Role> getAllRoles();

    void updateAccountExpiryStatus(Long userId, boolean expire);

    void updateAccountEnabledStatus(Long userId, boolean enabled);

    void updateCredentialsExpiryStatus(Long userId, boolean expire);

    void updatePassword(Long userId, String currPassword, String password);

    // Admin
    void updatePassword(Long userId, String password);

    void generatePasswordResetToken(String email);

    void resetPassword(String token, String newPassword);

    Optional<User> findByEmail(String email);

    User getUser(final String verificationToken);

    // OAuth 2.0
    User registerUser(User user);

    User registerNewUserAccount(SignupRequest request);

    void deleteUser(User user);

    void createVerificationTokenForUser(User user, String token);

    VerificationToken getVerificationToken(String VerificationToken);

    VerificationToken generateNewVerificationToken(String token);

    String validateVerificationToken(String token);

    GoogleAuthenticatorKey generate2FASecret(Long userId);

    boolean validate2FACode(Long userId, int code);

    void enable2FA(Long userId);

    void disable2FA(Long userId);

    List<String> getUsersFromSessionRegistry();


    UserDTO findUserWithdefaultPaymentMethod(User user);

}
