package com.test.authx.controller;

import com.test.authx.domain.Result;
import com.test.authx.utils.JwtUtil;
import jakarta.annotation.Resource;
import org.springframework.core.io.ClassPathResource;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;


import java.util.Map;
@RestController
public class LoginController {
    @Resource
    private AuthenticationManager authenticationManager;
    @Resource
    private UserDetailsService userDetailsService;
    @Resource
    private JwtUtil jwtUtil;

    @GetMapping("/login")
    public ResponseEntity<ClassPathResource> showLoginPage() {
        ClassPathResource resource = new ClassPathResource("static/login.html");
        HttpHeaders headers = new HttpHeaders();
        headers.add(HttpHeaders.CONTENT_TYPE, "text/html;charset=UTF-8");
        return new ResponseEntity<>(resource, headers, HttpStatus.OK);
    }


    @PostMapping("/login")
    public Result<Map<String, String>> doLogin(@RequestBody LoginRequest loginRequest) {
        try {
            // 1. 校验账号密码
            authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(
                            loginRequest.getUsername(),
                            loginRequest.getPassword()
                    )
            );

            // 2. 生成 JWT Token
            UserDetails userDetails = userDetailsService.loadUserByUsername(loginRequest.getUsername());
            String token = jwtUtil.InitJwt(userDetails);

            // 3. 返回 Token
            return Result.success("登录成功", Map.of(
                    "token", token,
                    "username", userDetails.getUsername()
            ));
        } catch (Exception e) {
            return Result.fail("用户名或密码错误");
        }
    }

    // 接收登录表单提交的参数
    static class LoginRequest {
        private String username;
        private String password;

        // getter/setter 必须有
        public String getUsername() { return username; }
        public void setUsername(String username) { this.username = username; }
        public String getPassword() { return password; }
        public void setPassword(String password) { this.password = password; }
    }
}
