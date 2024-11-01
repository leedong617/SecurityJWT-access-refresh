package com.ex.controller;

import java.util.Collection;
import java.util.Iterator;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

@RestController
public class MainController {
	
	@GetMapping("/")
    public String mainP(HttpServletRequest request, HttpServletResponse response) {
		String id = SecurityContextHolder.getContext().getAuthentication().getName();
		
		Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

		Collection<? extends GrantedAuthority> authorities = authentication.getAuthorities();
		Iterator<? extends GrantedAuthority> iter = authorities.iterator();
		GrantedAuthority auth = iter.next();
		String role = auth.getAuthority();
		
		System.out.println(role);
		
		String token = request.getHeader("Authorization");
		System.out.println(token);
		
        return id+" / "+role;
    }
	
}
