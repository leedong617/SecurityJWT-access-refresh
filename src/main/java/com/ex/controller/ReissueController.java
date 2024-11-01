package com.ex.controller;


import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

import com.ex.jwt.JWTUtil;
import com.ex.service.ReissueService;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;

@RestController
@RequiredArgsConstructor
public class ReissueController {
	
	private final ReissueService reissueService;
	
	@PostMapping("/reissue")
	public ResponseEntity<?> reissue(HttpServletRequest request, HttpServletResponse response) {
		
		String refresh = reissueService.getRefreshToken(request);
		
		if (refresh == null)
            return new ResponseEntity<>("refresh token null", HttpStatus.BAD_REQUEST);
        
		
		if (!reissueService.expiredCheck(refresh))
            return new ResponseEntity<>("refresh token expired", HttpStatus.BAD_REQUEST);
		
		
		if (!reissueService.refreshCheck(refresh))
			return new ResponseEntity<>("invalid refresh token", HttpStatus.BAD_REQUEST);
		
		if(!reissueService.dbCheck(refresh))
			return new ResponseEntity<>("invalid refresh token", HttpStatus.BAD_REQUEST);
		
		//make new JWT
		String[] newJWT = reissueService.createNewJWT(refresh);
		String newAccess = newJWT[0];
		String newRefresh = newJWT[1];
		
		//Refresh 토큰 저장 DB에 기존의 Refresh 토큰 삭제 후 새 Refresh 토큰 저장
		reissueService.changeRefreshToken(refresh, reissueService.getUsername(newRefresh), newRefresh);
		
		//response
		response.setHeader("Authorization", "Bearer " + newAccess);
		response.addCookie(createCookie("refresh", newRefresh));
		return new ResponseEntity<>(HttpStatus.OK);
	}
	
	private Cookie createCookie(String key, String value) {
    	
        Cookie cookie = new Cookie(key, value);
        //refresh token 생명주기와 같음
        cookie.setMaxAge(60*60);
        //Https사용시 필요
        //cookie.setSecure(true);
        //쿠키 적용 범위
        //cookie.setPath("/");
        //javascript로 쿠키접근차단
        cookie.setHttpOnly(true);
        
        return cookie;
    }
}
