package com.ex.jwt;

import java.io.IOException;
import java.io.PrintWriter;
import java.util.Collection;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import com.ex.dto.CustomUserDetails;
import com.ex.entity.UserEntity;

import io.jsonwebtoken.ExpiredJwtException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
public class JWTFilter extends OncePerRequestFilter {
	
	private final JWTUtil jwtUtil;
	
	
	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {
		// 헤더에서 access키에 담긴 토큰을 꺼냄
		String accessToken = request.getHeader("Authorization");
		System.out.println(accessToken);
		// 토큰이 없다면 다음 필터로 넘김
		if (accessToken == null) {
			System.out.println("token null");
		    filterChain.doFilter(request, response);

		    return;
		}

		// 토큰 만료 여부 확인, 만료시 다음 필터로 넘기지 않음
		try {
		    jwtUtil.isExpired(accessToken);
		} catch (ExpiredJwtException e) {

		    //response body
		    PrintWriter writer = response.getWriter();
		    writer.print("access token expired");

		    //response status code
		    response.setStatus(401);
		    return;
		}

		// 토큰이 access인지 확인 (발급시 페이로드에 명시)
		String category = jwtUtil.getCategory(accessToken);

		if (!category.equals("access")) {

		    //response body
		    PrintWriter writer = response.getWriter();
		    writer.print("invalid access token");

		    //response status code
		    response.setStatus(401);
		    return;
		}

		// username, role 값을 획득
		String username = jwtUtil.getUsername(accessToken);
		String role = jwtUtil.getRole(accessToken);
		
		
		UserEntity userEntity = new UserEntity();
		userEntity.setUsername(username);
		userEntity.setRole(role);
		
		System.out.println(role);
		
		CustomUserDetails customUserDetails = new CustomUserDetails(userEntity);

		Authentication authToken = new UsernamePasswordAuthenticationToken(customUserDetails, null, customUserDetails.getAuthorities());
		
		Collection<? extends GrantedAuthority> auths = authToken.getAuthorities();
		for (GrantedAuthority grantedAuthority : auths) {
			System.out.println(grantedAuthority.getAuthority());
			
		}
		
		SecurityContextHolder.getContext().setAuthentication(authToken);

		filterChain.doFilter(request, response);
	}
	
}
