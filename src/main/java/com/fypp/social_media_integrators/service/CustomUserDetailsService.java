package com.fypp.social_media_integrators.service;


import com.fypp.social_media_integrators.entities.User;
import com.fypp.social_media_integrators.repositories.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.*;
import org.springframework.stereotype.Service;
import java.util.Collections;
@Service
public class CustomUserDetailsService  implements UserDetailsService {
    @Autowired
    private UserRepository userRepository;
    @Override
    public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
        User user = userRepository.findByEmail(email);
        if (user == null) {
            throw new UsernameNotFoundException("User Not Found with username: " + email);
        }
        return new org.springframework.security.core.userdetails.User(

                user.getEmail(),
                user.getPassword(),
                Collections.emptyList()
        );
    }
}