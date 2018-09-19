package io.github.mufasa1976.spring.oauth2.authenticationserver.services;

import lombok.RequiredArgsConstructor;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.ClientRegistrationException;
import org.springframework.security.oauth2.provider.NoSuchClientException;

@RequiredArgsConstructor
public class RedisClientDetailsService implements ClientDetailsService {
  private final RedisClientDetailsManager clientDetailsManager;

  @Override
  public ClientDetails loadClientByClientId(String clientId) throws ClientRegistrationException {
    return clientDetailsManager.getClientByClientId(clientId)
                               .orElseThrow(() -> new NoSuchClientException(clientId));
  }
}
