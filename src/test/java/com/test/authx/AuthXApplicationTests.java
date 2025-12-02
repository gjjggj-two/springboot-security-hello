package com.test.authx;

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

@SpringBootTest
class AuthXApplicationTests {

    @Test
    void contextLoads() {
    }
    @Test
    void TestPassword() {
        BCryptPasswordEncoder encoder = new BCryptPasswordEncoder();
        String encodedPwd = encoder.encode("123456"); // 明文密码
        System.out.println("123456 加密后的密文：" + encodedPwd);
    }
}
