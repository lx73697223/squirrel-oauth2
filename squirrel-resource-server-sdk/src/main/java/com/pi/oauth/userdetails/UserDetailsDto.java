package com.pi.oauth.userdetails;

import java.util.Collection;

import org.springframework.security.core.GrantedAuthority;

import lombok.Data;

@Data
public class UserDetailsDto implements MutableUserDetails {

    private static final long serialVersionUID = -1111249657131740219L;

    private Collection<? extends GrantedAuthority> authorities;

    private String password;

    private String username;

    private String phone;

    private String id;

    private boolean accountNonExpired;

    private boolean accountNonLocked;

    private boolean credentialsNonExpired;

    private boolean enabled;

}
