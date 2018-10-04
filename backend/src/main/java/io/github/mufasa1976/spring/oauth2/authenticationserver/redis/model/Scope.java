package io.github.mufasa1976.spring.oauth2.authenticationserver.redis.model;

import lombok.Data;
import org.springframework.data.annotation.Id;
import org.springframework.data.redis.core.RedisHash;

@Data
@RedisHash("scopes")
public class Scope {
  @Id
  private String scope;
  private String description;
}
