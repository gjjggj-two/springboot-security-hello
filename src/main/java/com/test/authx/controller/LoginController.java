package com.test.authx.controller;

import com.test.authx.utils.JwtUtil;
import jakarta.annotation.Resource;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;
import java.util.Map;

@RestController
public class LoginController {
    // 注入认证管理器（Spring Security 配置的 Bean）
    @Resource
    private AuthenticationManager authenticationManager;

    // 注入 UserDetailsService（查询用户信息）
    @Resource
    private UserDetailsService userDetailsService;

    // 注入 JWT 工具类（生成 Token）
    @Resource
    private JwtUtil jwtUtil;

    /**
     * 登录接口：POST /login
     * 接收用户名密码，认证成功后返回 Token
     */
    @PostMapping("/login")
    public ResponseEntity<Map<String, Object>> login(
            // 接收请求体的用户名密码（和你 ApiFox 传的 JSON 字段对应）
            @RequestBody LoginRequest loginRequest
    ) {
        try {
            // 1. 调用 Spring Security 认证管理器，校验用户名密码
            authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(
                            loginRequest.getUsername(),
                            loginRequest.getPassword()
                    )
            );
        } catch (Exception e) {
            // 认证失败（用户名/密码错误）
            Map<String, Object> errorResult = new HashMap<>();
            errorResult.put("code", 401);
            errorResult.put("msg", "用户名或密码错误");
            return ResponseEntity.ok(errorResult);
        }

        // 2. 认证成功，查询用户详情
        UserDetails userDetails = userDetailsService.loadUserByUsername(loginRequest.getUsername());

        // 3. 生成 JWT Token
        String token = jwtUtil.InitJwt(userDetails);

        // 4. 构造返回结果
        Map<String, Object> successResult = new HashMap<>();
        successResult.put("code", 200);
        successResult.put("msg", "登录成功");
        successResult.put("data", Map.of(
                "token", token,
                "username", userDetails.getUsername()
        ));

        return ResponseEntity.ok(successResult);
    }

    // 内部静态类：接收请求体参数（和 JSON 字段对应）
    static class LoginRequest {
        private String username;
        private String password;

        // 必须有 getter/setter（Spring 才能自动绑定请求体）
        public String getUsername() {
            return username;
        }

        public void setUsername(String username) {
            this.username = username;
        }

        public String getPassword() {
            return password;
        }

        public void setPassword(String password) {
            this.password = password;
        }
    }
}
