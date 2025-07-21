package com.maria.t1_auth.repository;

import com.maria.t1_auth.model.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface UserRepository extends JpaRepository<User, Long> {
    User getUserByUsername(String username);

    boolean existsByUsername(String username);
    boolean existsByEmail(String email);
}
