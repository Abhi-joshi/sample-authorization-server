package com.abhishek.sampleauthorizationserver.repository;

import com.abhishek.sampleauthorizationserver.model.EndUser;
import org.springframework.data.jpa.repository.JpaRepository;

public interface EndUsersRepository extends JpaRepository<EndUser, Long> {

    EndUser findByUsername(String username);

}
