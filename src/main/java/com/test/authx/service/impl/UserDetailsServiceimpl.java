package com.test.authx.service.impl;

import com.baomidou.mybatisplus.extension.service.impl.ServiceImpl;
import com.test.authx.domain.User;
import com.test.authx.mapper.UserMapper;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
public class UserDetailsServiceimpl extends ServiceImpl<UserMapper, User> implements UserDetailsService {
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {

        User user = this.lambdaQuery()
                .eq(User::getUsername, username)
                .one(); // 查询一条记录
        if (user == null) {
            throw new UsernameNotFoundException("用户名或密码错误");
        }
        return user;
    }
}
