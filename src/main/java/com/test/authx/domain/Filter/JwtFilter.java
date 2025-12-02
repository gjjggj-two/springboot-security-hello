package com.test.authx.domain.Filter;

import com.fasterxml.jackson.databind.ObjectMapper;
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
import java.util.Map;

@Component
public class JwtFilter extends OncePerRequestFilter {
    private final JwtUtil jwtUtil;
    private final UserDetailsService userDetailsService;
    private final ObjectMapper objectMapper = new ObjectMapper();

    public JwtFilter(JwtUtil jwtUtil, UserDetailsService userDetailsService) {
        this.jwtUtil = jwtUtil;
        this.userDetailsService = userDetailsService;
    }

    @Override
    protected void doFilterInternal(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain filterChain
    ) throws ServletException, IOException, IOException {

        String requestUri = request.getRequestURI();
        String requestMethod = request.getMethod();
        System.out.println("JwtFilter 接收请求：URI=" + requestUri + "，方法=" + requestMethod);
        // 放行 GET/POST /login
        if ("/login".equals(requestUri) && ("GET".equalsIgnoreCase(requestMethod) || "POST".equalsIgnoreCase(requestMethod))) {
            filterChain.doFilter(request, response);
            return;
        }

        // 1. 从请求头中提取 Token
        String authorizationHeader = request.getHeader("Authorization");
        String token = null;
        String username = null;

        if (authorizationHeader != null && authorizationHeader.startsWith("Bearer ")) {
            token = authorizationHeader.substring(7);
            try {
                username = jwtUtil.takeUsername(token);
            } catch (Exception e) {
                response.setContentType("application/json;charset=UTF-8");
                response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                response.getWriter().write(objectMapper.writeValueAsString(
                        Map.of("code", 401, "msg", "Token 无效或已过期")
                ));
                return;
            }
        }

        // 请求头没拿到Token
        if (token == null) {
            token = request.getParameter("token"); // 从URL参数取Token
            System.out.println("从URL参数获取Token：" + (token != null ? token.substring(0, 10) + "..." : "null"));
        }

        // URL参数拿到了Token
        if (token != null && username == null) {
            try {
                username = jwtUtil.takeUsername(token);
                System.out.println("URL参数Token解析出的用户名：" + username);
            } catch (Exception e) {
                response.setContentType("application/json;charset=UTF-8");
                response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                response.getWriter().write(objectMapper.writeValueAsString(
                        Map.of("code", 401, "msg", "URL中的Token无效或已过期")
                ));
                return;
            }
        }

        // 2：无 Token 直接返回 401
        if (username == null) {
            response.setContentType("application/json;charset=UTF-8");
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            response.getWriter().write(objectMapper.writeValueAsString(
                    Map.of("code", 401, "msg", "请先登录获取 Token")
            ));
            return;
        }

        // 3. 如果 Token 解析出用户名
        if (SecurityContextHolder.getContext().getAuthentication() == null) {
            UserDetails userDetails = userDetailsService.loadUserByUsername(username);

            // 5. 验证 Token 是否有效
            if (jwtUtil.AuthJwt(token, userDetails)) {
                UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(
                        userDetails, null, userDetails.getAuthorities()
                );
                authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                SecurityContextHolder.getContext().setAuthentication(authentication);
            } else {
                response.setContentType("application/json;charset=UTF-8");
                response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                response.getWriter().write(objectMapper.writeValueAsString(
                        Map.of("code", 401, "msg", "Token 校验失败")
                ));
                return;
            }
        }

        // 7. 放行请求
        filterChain.doFilter(request, response);
    }
}