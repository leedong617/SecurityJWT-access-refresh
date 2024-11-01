package com.ex.controller;

import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

import com.ex.dto.JoinDTO;
import com.ex.service.JoinService;

import lombok.RequiredArgsConstructor;

@RestController
@RequiredArgsConstructor
public class JoinController {
	
	private final JoinService joinService;
	
	@PostMapping("/join")
	public String joinProcess(JoinDTO dto) {
		
		System.out.println(dto.getUsername());
        joinService.joinProcess(dto);
		
		return "ok";
	}
	
}
