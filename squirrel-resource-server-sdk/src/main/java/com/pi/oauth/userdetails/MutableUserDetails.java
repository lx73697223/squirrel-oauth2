package com.pi.oauth.userdetails;

import java.util.Collection;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

public interface MutableUserDetails extends UserDetails {

    void setAuthorities(Collection<? extends GrantedAuthority> authorities);

}
