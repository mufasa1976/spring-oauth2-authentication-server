package io.github.mufasa1976.spring.oauth2.authenticationserver.redis.model;

import lombok.Data;
import org.springframework.data.annotation.Id;
import org.springframework.data.redis.core.RedisHash;

import java.util.Set;

@Data
@RedisHash("ldapGroupToScopeMappings")
public class LdapGroupToScopeMapping {
  @Id
  private String ldapGroup;
  private Set<String> scopes;
}
