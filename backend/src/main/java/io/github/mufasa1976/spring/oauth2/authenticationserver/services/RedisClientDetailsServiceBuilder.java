package io.github.mufasa1976.spring.oauth2.authenticationserver.services;

import io.github.mufasa1976.spring.oauth2.authenticationserver.config.AuthorizationServerConfiguration;
import io.github.mufasa1976.spring.oauth2.authenticationserver.model.RedisClientDetails;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.oauth2.config.annotation.builders.ClientDetailsServiceBuilder;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;

import java.util.HashSet;
import java.util.Set;

@RequiredArgsConstructor
@Slf4j
public class RedisClientDetailsServiceBuilder extends ClientDetailsServiceBuilder<RedisClientDetailsServiceBuilder> {
  private final RedisClientDetailsManager clientDetailsManager;
  private final String internalClientName;

  private Set<RedisClientDetails> redisClientDetails = new HashSet<>();

  @Override
  protected void addClient(String clientId, ClientDetails clientDetails) {
    BaseClientDetails baseClientDetails = (BaseClientDetails) clientDetails;
    redisClientDetails.add(RedisClientDetails.copyFrom(baseClientDetails));
  }

  @Override
  protected ClientDetailsService performBuild() {
    RedisClientDetailsService clientDetailsService = new RedisClientDetailsService(clientDetailsManager);
    redisClientDetails.forEach(clientDetails -> {
      if (clientDetailsManager.existsClient(clientDetails.getClientId())) return;
      log.info("Save new ClientDetails with clientId {}", clientDetails.getClientId());
      extendInformationOnInternalClient(clientDetails);
      clientDetailsManager.saveClient(clientDetails);
    });
    return clientDetailsService;
  }

  private void extendInformationOnInternalClient(RedisClientDetails clientDetails) {
    if (isNotInternalClient(clientDetails.getClientId())) return;
    clientDetails.setClientName(internalClientName);
  }

  private boolean isNotInternalClient(String clientId) {
    return !AuthorizationServerConfiguration.INTERNAL_CLIENT_ID.equals(clientId);
  }
}
