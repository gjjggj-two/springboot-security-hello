package com.test.authx;

import org.mybatis.spring.annotation.MapperScan;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@MapperScan("com.test.authx.mapper")
@SpringBootApplication
public class AuthXApplication {

    public static void main(String[] args) {
        SpringApplication.run(AuthXApplication.class, args);
    }

}
