package io.github.mufasa1976.spring.oauth2.authenticationserver.config;

import org.springframework.ldap.core.DirContextOperations;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.authority.mapping.GrantedAuthoritiesMapper;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.ldap.userdetails.InetOrgPersonContextMapper;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

public class MyUserDetailsContextMapper extends InetOrgPersonContextMapper implements GrantedAuthoritiesMapper {
  @Override
  public UserDetails mapUserFromContext(DirContextOperations ctx, String username, Collection<? extends GrantedAuthority> authorities) {
    return super.mapUserFromContext(ctx, username, mapAuthorities(authorities));
  }

  @Override
  public Collection<? extends GrantedAuthority> mapAuthorities(Collection<? extends GrantedAuthority> authorities) {
    List<GrantedAuthority> modifiedAuthorities = new ArrayList<>();
    authorities.stream()
               .map(GrantedAuthority::getAuthority)
               .map(authority -> new SimpleGrantedAuthority("ROLE_MODIFIED_" + authority))
               .forEach(modifiedAuthorities::add);
    return modifiedAuthorities;
  }
}
