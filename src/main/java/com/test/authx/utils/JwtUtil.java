package com.test.authx.utils;


import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import java.util.Date;
@Component
public class JwtUtil {
    /**
     * 初始化生成JWT令牌
     * @param user
     * @return
     */
    public String InitJwt(UserDetails user) {
        String key = "ZG9uZ3h1ZXFpbnF3ZXJ0eXVpb3Bsa2poZ2Zkc2F6eGN2Ym5t";
        long expiration = System.currentTimeMillis() + 3600 * 1000;
         return Jwts.builder()
                .setSubject(user.getUsername()) // Token 中存储用户名
                .setIssuedAt(new Date()) // 签发时间
                .setExpiration(new Date(System.currentTimeMillis() + expiration)) // 过期时间
                .signWith(SignatureAlgorithm.HS256,key)
                .compact();
    }

    /**
     * 认证jwt
     * @param token
     * @param user
     * @return
     */
    public boolean AuthJwt(String token, UserDetails user) {
        String username = takeUsername(token);
        return username.equals(user.getUsername()) && !isTokenExpire(token);
    }

    /**
     * 获取姓名
     * @param token
     * @return
     */
    public String takeUsername(String token) {
        return takeClaims(token).getSubject();
    }

    /**
     * 获取声明
     * @param token
     * @return
     */
    private Claims takeClaims(String token) {
        String key = "ZG9uZ3h1ZXFpbnF3ZXJ0eXVpb3Bsa2poZ2Zkc2F6eGN2Ym5t";
        return  Jwts.parserBuilder()
                .setSigningKey(key)
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    /**
     * 是否过期
     * @param token
     * @return
     */
    private boolean isTokenExpire(String token) {
        return takeClaims(token).getExpiration().before(new Date());
    }
}
