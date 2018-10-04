package io.github.mufasa1976.spring.oauth2.authenticationserver.redis.model;

import lombok.Builder;
import lombok.Data;
import org.springframework.data.annotation.Id;
import org.springframework.data.redis.core.RedisHash;

import java.util.Set;

@Data
@Builder
@RedisHash("scopeMappings")
public class ScopeMapping {
  @Id
  private String group;
  private Set<String> scopes;
}
