package com.ex.service;

import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import com.ex.dto.JoinDTO;
import com.ex.entity.UserEntity;
import com.ex.repository.UserRepository;

import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class JoinService {
	
	private final UserRepository userRepository;
	private final BCryptPasswordEncoder bCryptPasswordEncoder;
    
	public void joinProcess(JoinDTO dto) {

        Boolean isExist = userRepository.existsByUsername(dto.getUsername());

        if (isExist) {
        	
            return;
        }

        UserEntity data = new UserEntity();

        data.setUsername(dto.getUsername());
        data.setPassword(bCryptPasswordEncoder.encode(dto.getPassword()));
        data.setRole("ROLE_ADMIN");

        userRepository.save(data);
    }
}
