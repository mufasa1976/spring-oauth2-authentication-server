package io.github.mufasa1976.spring.oauth2.authenticationserver.config;

import io.github.mufasa1976.spring.oauth2.authenticationserver.ApplicationProperties;
import io.github.mufasa1976.spring.oauth2.authenticationserver.redis.model.ScopeMapping;
import io.github.mufasa1976.spring.oauth2.authenticationserver.redis.repositories.ScopeMappingRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.ldap.core.DirContextOperations;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.authority.mapping.GrantedAuthoritiesMapper;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.ldap.userdetails.InetOrgPersonContextMapper;
import org.springframework.stereotype.Component;

import java.util.*;

@Component
@RequiredArgsConstructor
public class ScopedInetOrgPersonContextMapper extends InetOrgPersonContextMapper implements GrantedAuthoritiesMapper {
  private final ScopeMappingRepository scopeMappingRepository;
  private final ApplicationProperties applicationProperties;

  @Override
  public UserDetails mapUserFromContext(DirContextOperations ctx, String username, Collection<? extends GrantedAuthority> authorities) {
    return super.mapUserFromContext(ctx, username, mapAuthorities(authorities));
  }

  @Override
  public Collection<? extends GrantedAuthority> mapAuthorities(Collection<? extends GrantedAuthority> authorities) {
    Set<GrantedAuthority> modifiedAuthorities = new HashSet<>();
    authorities.stream()
               .map(GrantedAuthority::getAuthority)
               .map(scopeMappingRepository::findById)
               .filter(Optional::isPresent)
               .map(Optional::get)
               .map(ScopeMapping::getScopes)
               .filter(Objects::nonNull)
               .flatMap(Set::stream)
               .map(SimpleGrantedAuthority::new)
               .forEach(modifiedAuthorities::add);
    authorities.stream()
               .map(GrantedAuthority::getAuthority)
               .filter(applicationProperties.getAllowedLdapGroupsForServerAdministration()::contains)
               .map(ignored -> new SimpleGrantedAuthority(AuthorizationServerConfiguration.INTERNAL_SCOPE))
               .forEach(modifiedAuthorities::add);
    return modifiedAuthorities;
  }
}
