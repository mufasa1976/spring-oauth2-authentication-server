package io.github.mufasa1976.spring.oauth2.authenticationserver.services;

import io.github.mufasa1976.spring.oauth2.authenticationserver.redis.model.RedisClientDetails;

import java.util.Optional;

public interface RedisClientDetailsManager {
  Optional<RedisClientDetails> getClientByClientId(String clientId);

  boolean existsClient(String clientId);

  RedisClientDetails saveClient(RedisClientDetails clientDetails);
}
