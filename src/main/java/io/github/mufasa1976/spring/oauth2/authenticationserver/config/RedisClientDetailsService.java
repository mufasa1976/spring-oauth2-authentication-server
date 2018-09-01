package io.github.mufasa1976.spring.oauth2.authenticationserver.config;

import lombok.RequiredArgsConstructor;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.ClientRegistrationException;

@RequiredArgsConstructor
public class RedisClientDetailsService implements ClientDetailsService {
  private final RedisTemplate<String, Object> redisTemplate;

  @Override
  public ClientDetails loadClientByClientId(String clientId) throws ClientRegistrationException {
    return null;
  }
}
