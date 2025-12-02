package com.test.authx.domain;

import com.test.authx.utils.JwtUtil;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import java.io.IOException;

@Component
public class JwtFilter extends OncePerRequestFilter {
    private final JwtUtil jwtUtil;
    private final UserDetailsService userDetailsService;

    // 构造方法注入依赖（Spring 自动注入）
    public JwtFilter(JwtUtil jwtUtil, UserDetailsService userDetailsService) {
        this.jwtUtil = jwtUtil;
        this.userDetailsService = userDetailsService;
    }
    @Override
    protected void doFilterInternal(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain filterChain
    ) throws ServletException, IOException {
        // 关键：直接判断请求路径是否是 /login，是则直接放行，不执行任何 Token 逻辑
        if ("/login".equals(request.getRequestURI())) {
            System.out.println("检测到 /login 请求，直接放行");
            filterChain.doFilter(request, response);
            return;
        }

        // 1. 从请求头中提取 Token（格式：Authorization: Bearer <token>）
        String authorizationHeader = request.getHeader("Authorization");
        String token = null;
        String username = null;

        if (authorizationHeader != null && authorizationHeader.startsWith("Bearer ")) {
            // 截取 Token（去掉 "Bearer " 前缀，空格后开始）
            token = authorizationHeader.substring(7);
            try {
                // 2. 解析 Token 得到用户名
                username = jwtUtil.extractUsername(token);
            } catch (Exception e) {
                // Token 无效（篡改/过期），直接放行，后续 Spring Security 会拦截未认证请求
                filterChain.doFilter(request, response);
                return;
            }
        }

        // 3. 如果 Token 解析出用户名，且当前上下文没有认证信息（避免重复认证）
        if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) {
            // 4. 从 UserDetailsService 中获取合法用户信息（你之前配置的 test 用户）
            UserDetails userDetails = userDetailsService.loadUserByUsername(username);

            // 5. 验证 Token 是否有效（用户名匹配 + 未过期）
            if (jwtUtil.validateJwt(token, userDetails)) {
                // 6. 构造认证对象，存入 Spring Security 上下文（表示已登录）
                UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(
                        userDetails, null, userDetails.getAuthorities()
                );
                // 设置请求详情（如 IP、Session 等）
                authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                // 存入上下文，后续接口可通过 SecurityContext 获取用户信息
                SecurityContextHolder.getContext().setAuthentication(authentication);
            }
        }

        // 7. 放行请求，继续执行后续过滤器（如访问 /hello 接口）
        filterChain.doFilter(request, response);
        System.out.println("请求头 Authorization：" + request.getHeader("Authorization"));
    }
}
