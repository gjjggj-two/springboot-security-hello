package com.test.authx.utils;

import com.test.authx.domain.User;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import java.util.Date;
@Component
public class JwtUtil {

    public String InitJwt(UserDetails user) {
        String key = "ZG9uZ3h1ZXFpbnF3ZXJ0eXVpb3Bsa2poZ2Zkc2F6eGN2Ym5t";
        long expiration = System.currentTimeMillis() + 3600 * 1000;
         return Jwts.builder()
                .setSubject(user.getUsername()) // Token 中存储用户名（主题）
                .setIssuedAt(new Date()) // 签发时间
                .setExpiration(new Date(System.currentTimeMillis() + expiration)) // 过期时间
                .signWith(SignatureAlgorithm.HS256,key) // 用密钥签名（防篡改）
                .compact();
    }

    public boolean validateJwt(String token, UserDetails user) {
        String username = extractUsername(token);
        return username.equals(user.getUsername()) && !isTokenExpire(token);
    }
    public String extractUsername(String token) {
        return extractClaims(token).getSubject();
    }
    private Claims extractClaims(String token) {
        String key = "ZG9uZ3h1ZXFpbnF3ZXJ0eXVpb3Bsa2poZ2Zkc2F6eGN2Ym5t";
        return  Jwts.parserBuilder()
                .setSigningKey(key)
                .build()
                .parseClaimsJws(token)
                .getBody();
    }
    private boolean isTokenExpire(String token) {
        return extractClaims(token).getExpiration().before(new Date());
    }
}
