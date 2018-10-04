package io.github.mufasa1976.spring.oauth2.authenticationserver.services;

import io.github.mufasa1976.spring.oauth2.authenticationserver.redis.model.RedisClientDetails;
import io.github.mufasa1976.spring.oauth2.authenticationserver.redis.repositories.RedisClientDetailsRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Optional;

@Service
@RequiredArgsConstructor
public class RedisClientDetailsManagerImpl implements RedisClientDetailsManager {
  private final RedisClientDetailsRepository repository;
  private final PasswordEncoder passwordEncoder;

  @Override
  public Optional<RedisClientDetails> getClientByClientId(String clientId) {
    return repository.findById(clientId);
  }

  @Override
  public boolean existsClient(String clientId) {
    return repository.existsById(clientId);
  }

  @Override
  @Transactional
  public RedisClientDetails saveClient(RedisClientDetails clientDetails) {
    if (clientDetails.isSecretRequired()) {
      clientDetails.setClientSecret(passwordEncoder.encode(clientDetails.getClientSecret()));
    }
    return repository.save(clientDetails);
  }
}
