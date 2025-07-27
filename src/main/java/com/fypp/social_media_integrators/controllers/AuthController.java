package com.fypp.social_media_integrators.controllers;



import com.fypp.social_media_integrators.dto.LoginDto;
import com.fypp.social_media_integrators.entities.RefreshToken;
import com.fypp.social_media_integrators.entities.User;
import com.fypp.social_media_integrators.repositories.RefreshTokenRepository;
import com.fypp.social_media_integrators.repositories.UserRepository;
import com.fypp.social_media_integrators.security.JwtUtil;
import com.fypp.social_media_integrators.service.RefreshTokenService;
import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.*;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;
import java.util.Optional;

@RestController
@RequestMapping("/api/auth")
public class AuthController {
    @Autowired
    AuthenticationManager authenticationManager;
    @Autowired
    UserRepository userRepository;
    @Autowired
    PasswordEncoder encoder;
    @Autowired
    JwtUtil jwtUtils;
    @Autowired
    private RefreshTokenRepository refreshTokenRepository;
    @Autowired
    private RefreshTokenService refreshTokenService;


//    @PostMapping("/signin")
//    public ResponseEntity<?> authenticateUser(@Valid @RequestBody LoginDto loginDto, BindingResult bindingResult) {
//
//
//        if (bindingResult.hasErrors()) {
//            List<String> errors = bindingResult.getFieldErrors().stream()
//                    .map(err -> err.getField() + ": " + err.getDefaultMessage())
//                    .toList();
//            return ResponseEntity.badRequest().body(errors);
//        }
//
//        // Check if user exists
//        Optional<User> userOpt = Optional.ofNullable(userRepository.findByEmail(loginDto.getEmail()));
//
//        if (userOpt.isEmpty()) {
//            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Email not registered");
//        }
//
//        User user = userOpt.get();
//
//        if (!encoder.matches(loginDto.getPassword(), user.getPassword())) {
//            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Invalid password");
//        }
//
//
//        Authentication authentication = authenticationManager.authenticate(
//                new UsernamePasswordAuthenticationToken(
//                        loginDto.getEmail(),
//                        loginDto.getPassword()
//                )
//        );
//
//
//
//        UserDetails userDetails = (UserDetails) authentication.getPrincipal();
//
//        return ResponseEntity.ok("Login Successfully   " + jwtUtils.generateToken(userDetails.getUsername()));
//
//
//    }

    @PostMapping("/signin")
    public Map<String, String> authenticateUser(@RequestBody User user) {
        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(user.getEmail(), user.getPassword())
        );

        UserDetails userDetails = (UserDetails) authentication.getPrincipal();
        String accessToken = jwtUtils.generateToken(userDetails.getUsername());

        User dbUser = userRepository.findByEmail(userDetails.getUsername());
        RefreshToken refreshToken = refreshTokenService.createRefreshToken(dbUser.getId());

        return Map.of(
                "accessToken", accessToken,
                "refreshToken", refreshToken.getToken()
        );
    }


    @PostMapping("/signup")
    public ResponseEntity<?> registerUser(@Valid @RequestBody User user, BindingResult bindingResult) {
        if (bindingResult.hasErrors()) {

            List<String> errors = bindingResult.getFieldErrors().stream()
                    .map(error -> error.getField() + ": " + error.getDefaultMessage())
                    .toList();
            return ResponseEntity.badRequest().body(errors);
        }


        if (userRepository.existsByEmail(user.getEmail())) {
            return ResponseEntity.ok("Error: Email is already taken!");
        }
        // Create new user's account
        User newUser = new User(
                null,
                user.getName(),
                user.getEmail(),
                encoder.encode(user.getPassword()
                ), user.getDateOfBirth()
        );
        userRepository.save(newUser);
        return ResponseEntity.ok("User registered successfully!");
    }

    @PostMapping("/refresh")
    public ResponseEntity<?> refreshToken(@RequestBody Map<String, String> payload) {
        String requestToken = payload.get("refreshToken");
        return refreshTokenRepository.findByToken(requestToken)
                .map(token -> {
                    if (refreshTokenService.isTokenExpired(token)) {
                        refreshTokenRepository.delete(token);
                        return ResponseEntity.badRequest().body("Refresh token expired. Please login again.");
                    }
                    String newJwt = jwtUtils.generateToken(token.getUser().getEmail());
                    return ResponseEntity.ok(Map.of("token", newJwt));
                })
                .orElse(ResponseEntity.badRequest().body("Invalid refresh token."));
    }

    @PostMapping("/logout")
    public ResponseEntity<?> logoutUser(@RequestBody Map<String, String> payload) {
        String requestToken = payload.get("refreshToken");

        if (requestToken == null || requestToken.isBlank()) {
            return ResponseEntity.badRequest().body("Refresh token is required.");
        }

        return refreshTokenRepository.findByToken(requestToken)
                .map(token -> {
                    refreshTokenRepository.delete(token);
                    return ResponseEntity.ok("Logged out successfully.");
                })
                .orElse(ResponseEntity.badRequest().body("Invalid refresh token."));
    }
}

