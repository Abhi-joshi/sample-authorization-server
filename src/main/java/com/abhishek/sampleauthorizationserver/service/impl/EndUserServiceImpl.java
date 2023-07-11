package com.abhishek.sampleauthorizationserver.service.impl;

import com.abhishek.sampleauthorizationserver.model.EndUser;
import com.abhishek.sampleauthorizationserver.repository.EndUsersRepository;
import com.abhishek.sampleauthorizationserver.service.EndUserService;
import jakarta.transaction.Transactional;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;

@Service
public class EndUserServiceImpl implements EndUserService {

    private final EndUsersRepository endUsersRepository;

    public EndUserServiceImpl(EndUsersRepository endUsersRepository) {
        this.endUsersRepository = endUsersRepository;
    }

    @Override
    @Transactional
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        EndUser user = this.endUsersRepository.findByUsername(username);
        List<GrantedAuthority> authorities = new ArrayList<>();
        user.getRoles().forEach(role -> authorities.add(new SimpleGrantedAuthority(role.getRole())));
        return new User(user.getUsername(), user.getPassword(), authorities);
    }

}
