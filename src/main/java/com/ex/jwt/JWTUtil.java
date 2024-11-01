package com.ex.jwt;

import java.nio.charset.StandardCharsets;
import java.util.Date;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import io.jsonwebtoken.Jwts;
@Component
public class JWTUtil {
/*	토큰 Payload에 저장될 정보

	username
	role
	생성일
	만료일
*/
/*	JWTUtil 구현 메소드

	JWTUtil 생성자
	username 확인 메소드
	role 확인 메소드
	만료일 확인 메소드
 */
	private final SecretKey secretKey;
	
	// JWTUtil 생성자
	public JWTUtil(@Value("${spring.jwt.secret}")String secret) {
		
		this.secretKey = new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), Jwts.SIG.HS256.key().build().getAlgorithm());
	}
	
	// username 확인 메소드
	public String getUsername(String token) {
		
		return Jwts.parser().verifyWith(secretKey).build().parseSignedClaims(token).getPayload().get("username", String.class);
	}
	
	// role 확인 메소드
	public String getRole(String token) {
		
		return Jwts.parser().verifyWith(secretKey).build().parseSignedClaims(token).getPayload().get("role", String.class);
	}
	
public String getCategory(String token) {
		
		return Jwts.parser().verifyWith(secretKey).build().parseSignedClaims(token).getPayload().get("category", String.class);
	}
	
	// 만료일 확인 메소드
	public Boolean isExpired(String token) {
		
		return Jwts.parser().verifyWith(secretKey).build().parseSignedClaims(token).getPayload().getExpiration().before(new Date());
	}
	
	//토큰 생성 메소드
	public String createJwt(String category, String username, String role, Long expiredMs) {
		return Jwts.builder()
				.claim("category", category)
				.claim("username", username)
				.claim("role", role)
				// 토큰 발행시간
				.issuedAt(new Date(System.currentTimeMillis()))
				// 토큰 소멸시간
				.expiration(new Date(System.currentTimeMillis() + expiredMs))
				.signWith(secretKey)
				.compact();
	}
	
}
