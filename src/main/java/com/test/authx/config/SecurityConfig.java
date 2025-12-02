package com.test.authx.config;

import com.test.authx.domain.JwtFilter;
import jakarta.annotation.Resource;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Resource
    private JwtFilter jwtFilter;

    @Resource
    private UserDetailsService userDetailsService;

    // 密码加密器（必须Bean，供认证提供者使用）
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    // 认证提供者：关联 UserDetailsService 和 PasswordEncoder（核心修复点）
    @Bean
    public DaoAuthenticationProvider authenticationProvider() {
        DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
        provider.setUserDetailsService(userDetailsService); // 自定义用户查询逻辑
        provider.setPasswordEncoder(passwordEncoder()); // 密码加密校验
        provider.setHideUserNotFoundExceptions(false); // 登录时显示「用户不存在」而非通用错误（可选）
        return provider;
    }

    // 认证管理器（供登录接口手动触发认证）
    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration config) throws Exception {
        return config.getAuthenticationManager();
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                // 1. 禁用 CSRF（JWT 无状态，无需 CSRF 防护）
                .csrf(csrf -> csrf.disable())
                // 2. 禁用 Session（JWT 无状态，不依赖 Session）
                .sessionManagement(session -> session
                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                )
                // 3. 接口权限控制
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/login").permitAll() // 登录接口放行
                        .requestMatchers("/swagger-ui/**", "/v3/api-docs/**").permitAll() // swagger 放行（可选）
                        .anyRequest().authenticated() // 其他接口需认证
                )
                // 4. 移除 formLogin（用 REST 接口替代表单登录）
                .formLogin(form -> form.disable())
                // 5. 移除默认 logout（如需登出，自定义接口清除 Token）
                .logout(logout -> logout.disable())
                // 6. 注册 JWT 过滤器（在用户名密码过滤器之前执行）
                .addFilterBefore(jwtFilter, UsernamePasswordAuthenticationFilter.class)
                // 7. 注入认证提供者（核心修复点）
                .authenticationProvider(authenticationProvider());

        return http.build();
    }
}