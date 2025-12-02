package com.test.authx.domain;

import com.baomidou.mybatisplus.annotation.TableName;
import jakarta.persistence.Column;
import jakarta.persistence.criteria.CriteriaBuilder;
import lombok.Data;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.time.LocalDateTime;
import java.util.Collection;
import java.util.Collections;

@Data
@TableName("userdetails")
public class User implements UserDetails {
    String username;
    @Column
    String password;
    private Integer status;
    private LocalDateTime createTime;
    private LocalDateTime updateTime;

    public Collection<? extends GrantedAuthority> getAuthorities() {
        return Collections.singletonList(new SimpleGrantedAuthority("ROLE_USER"));
    }

    @Override
    public String getPassword() {
        return this.password;
    }

    /**
     * 3. 用户名（直接返回数据库中的 username）
     */
    @Override
    public String getUsername() {
        return this.username;
    }

    /**
     * 4. 账号是否未过期（简化：永远不过期）
     */
    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    /**
     * 5. 账号是否未锁定（简化：永远不锁定）
     */
    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    /**
     * 6. 密码是否未过期（简化：永远不过期）
     */
    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    /**
     * 7. 账号是否启用（关联数据库 status 字段：1-启用，0-禁用）
     */
    @Override
    public boolean isEnabled() {
        return this.status == 1;
    }

}
