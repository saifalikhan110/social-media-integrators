package com.fypp.social_media_integrators.repositories;


import com.fypp.social_media_integrators.entities.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
@Repository
public interface UserRepository extends JpaRepository<User, Long> {


    User findByEmail(String email);
    boolean existsByEmail(String email);
}