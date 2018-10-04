package io.github.mufasa1976.spring.oauth2.authenticationserver.redis.model;

import lombok.Builder;
import lombok.Data;
import org.springframework.data.annotation.Id;
import org.springframework.data.redis.core.RedisHash;

@Data
@Builder
@RedisHash("scopes")
public class Scope {
  @Id
  private String name;
  private String description;
}
