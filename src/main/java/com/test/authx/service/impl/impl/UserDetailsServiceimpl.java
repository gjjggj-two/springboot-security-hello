package com.test.authx.service.impl.impl;

import com.baomidou.mybatisplus.extension.service.impl.ServiceImpl;
import com.test.authx.domain.User;
import com.test.authx.mapper.UserMapper;
import jakarta.annotation.Resource;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
public class UserDetailsServiceimpl extends ServiceImpl<UserMapper, User> implements UserDetailsService {
    @Resource
    private UserMapper userDetailsMapper;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        System.out.println("=== 正在查询用户 ===");
        System.out.println("传入的用户名：" + username); // 看前端传的用户名是什么


        // 用 MyBatis-Plus 3.x 正确的 lambdaQuery 写法（无硬编码）
        User user = this.lambdaQuery()
                .eq(User::getUsername, username) // 注意：User 实体必须有 getUsername() 方法（@Data 已生成）
                .one(); // 查询一条记录（无结果返回 null）
        System.out.println("数据库中的加密密码：" + user.getPassword()); // 看是否能拿到加密串
        if (user == null) {
            throw new UsernameNotFoundException("用户名或密码错误");
        }
        return user;
    }
}
