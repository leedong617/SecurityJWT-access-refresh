package com.ex.service;

import java.sql.Date;

import org.springframework.stereotype.Service;

import com.ex.entity.RefreshEntity;
import com.ex.jwt.JWTUtil;
import com.ex.repository.RefreshRepository;

import io.jsonwebtoken.ExpiredJwtException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class ReissueService {
	
	private final JWTUtil jwtUtil;
	private final RefreshRepository refreshRepository;
	
	//username얻기
	public String getUsername(String refreshToken) {
		return jwtUtil.getUsername(refreshToken);
	}
	
	//리프레시 토큰 얻기
	public String getRefreshToken(HttpServletRequest request) {
		//get refresh token
        String refresh = null;
        Cookie[] cookies = request.getCookies();
        for (Cookie cookie : cookies) {

            if (cookie.getName().equals("refresh")) {

                refresh = cookie.getValue();
                return refresh;
            }
        }
        return refresh;
	}
	// 토큰이 만료되었는지 체크
	public boolean expiredCheck(String refreshToken) {
		try {
			jwtUtil.isExpired(refreshToken);
		} catch (ExpiredJwtException e) {
			return false;
		}
		return true;
	}
	//리프레시 토큰인지 체크
	public boolean refreshCheck(String refreshToken) {
		String category = jwtUtil.getCategory(refreshToken);

        if (!category.equals("refresh"))
        	return false;
        
        return true;
	}
	//JWT생성
	public String[] createNewJWT(String refreshToken) {
		String[] newTokens = new String[2];
		
		String username = jwtUtil.getUsername(refreshToken);
        String role = jwtUtil.getRole(refreshToken);

        //make new JWT
        String newAccess = jwtUtil.createJwt("access", username, role, 600000L);
        //RTR (Refresh Token Rotation)
        String newRefresh = jwtUtil.createJwt("refresh", username, role, 600000L*6);
        
        newTokens[0] = newAccess;
        newTokens[1] = newRefresh;
        
        return newTokens;
	}
	//db에 refresh token이 저장되어있는지 체크
	public boolean dbCheck(String refreshToken) {
		boolean isExist = refreshRepository.existsByRefresh(refreshToken);
		if (!isExist) {
			return false;
		}
		return true;
	}
	
	public void changeRefreshToken(String refreshToken, String username, String newRefresh) {
		//Refresh 토큰 저장 DB에 기존의 Refresh 토큰 삭제 후 새 Refresh 토큰 저장
		refreshRepository.deleteByRefresh(refreshToken);
		addRefreshEntity(username, newRefresh, 600000L*6);
	}
	
	private void addRefreshEntity(String username, String refresh, Long expiredMs) {

	    Date date = new Date(System.currentTimeMillis() + expiredMs);

	    RefreshEntity refreshEntity = new RefreshEntity();
	    refreshEntity.setUsername(username);
	    refreshEntity.setRefresh(refresh);
	    refreshEntity.setExpiration(date.toString());

	    refreshRepository.save(refreshEntity);
	}
}
