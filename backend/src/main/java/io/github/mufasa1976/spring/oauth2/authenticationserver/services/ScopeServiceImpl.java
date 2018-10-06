package io.github.mufasa1976.spring.oauth2.authenticationserver.services;

import io.github.mufasa1976.spring.oauth2.authenticationserver.config.AuthorizationServerConfiguration;
import io.github.mufasa1976.spring.oauth2.authenticationserver.exception.*;
import io.github.mufasa1976.spring.oauth2.authenticationserver.redis.model.RedisClientDetails;
import io.github.mufasa1976.spring.oauth2.authenticationserver.redis.model.ScopeMapping;
import io.github.mufasa1976.spring.oauth2.authenticationserver.redis.repositories.RedisClientDetailsRepository;
import io.github.mufasa1976.spring.oauth2.authenticationserver.redis.repositories.ScopeMappingRepository;
import io.github.mufasa1976.spring.oauth2.authenticationserver.redis.repositories.ScopeRepository;
import lombok.Builder;
import lombok.RequiredArgsConstructor;
import lombok.Singular;
import lombok.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.CollectionUtils;

import javax.validation.constraints.NotNull;
import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.stream.Collectors;
import java.util.stream.StreamSupport;

@Service
@RequiredArgsConstructor
public class ScopeServiceImpl implements ScopeService {
  private final ScopeRepository scopeRepository;
  private final ScopeMappingRepository scopeMappingRepository;
  private final RedisClientDetailsRepository redisClientDetailsRepository;

  @Value
  @Builder
  private final static class ScopeImpl implements Scope {
    private String name;
    private String description;
    @Singular
    private Set<String> mappedClients;
    @Singular
    private Set<String> mappedGroups;
  }

  @Override
  public List<Scope> getScopes() {
    return StreamSupport.stream(scopeRepository.findAll().spliterator(), false)
                        .map(this::mapScope)
                        .collect(Collectors.toList());
  }

  private ScopeService.Scope mapScope(io.github.mufasa1976.spring.oauth2.authenticationserver.redis.model.Scope scope) {
    return ScopeImpl.builder()
                    .name(scope.getName())
                    .description(scope.getDescription())
                    .mappedClients(getMappedClients(scope))
                    .mappedGroups(getMappedGroups(scope))
                    .build();
  }

  private Set<String> getMappedClients(io.github.mufasa1976.spring.oauth2.authenticationserver.redis.model.Scope scope) {
    return StreamSupport.stream(redisClientDetailsRepository.findAll().spliterator(), false)
                        .filter(redisClientDetails -> redisClientDetails.getScope().contains(scope.getName()))
                        .map(RedisClientDetails::getClientId)
                        .collect(Collectors.toSet());
  }

  private Set<String> getMappedGroups(io.github.mufasa1976.spring.oauth2.authenticationserver.redis.model.Scope scope) {
    return StreamSupport.stream(scopeMappingRepository.findAll().spliterator(), false)
                        .filter(scopeMapping -> scopeMapping.getScopes().contains(scope.getName()))
                        .map(ScopeMapping::getGroup)
                        .collect(Collectors.toSet());
  }

  @Override
  public Optional<Scope> getScope(@NotNull String name) {
    return scopeRepository.findById(name)
                          .map(this::mapScope);
  }

  @Override
  @Transactional
  public boolean saveScope(@NotNull String name, String description) {
    checkForInternalAdministrationScope(name);

    AtomicBoolean created = new AtomicBoolean(false);
    io.github.mufasa1976.spring.oauth2.authenticationserver.redis.model.Scope scope =
        scopeRepository.findById(name)
                       .orElseGet(() -> {
                         created.set(true);
                         return io.github.mufasa1976.spring.oauth2.authenticationserver.redis.model.Scope.builder()
                                                                                                         .name(name)
                                                                                                         .build();
                       });
    scope.setDescription(description);
    scopeRepository.save(scope);
    return created.get();
  }

  private void checkForInternalAdministrationScope(@NotNull String scope) {
    if (scope.equals(AuthorizationServerConfiguration.INTERNAL_SCOPE)) {
      throw new InternalAdministrationScopeNotAllowedException();
    }
  }

  @Override
  @Transactional
  public void deleteScope(@NotNull String scope, boolean forced) throws ScopeNotRegisteredException {
    Optional<io.github.mufasa1976.spring.oauth2.authenticationserver.redis.model.Scope> existingScope = scopeRepository.findById(scope);
    if (!existingScope.isPresent()) {
      throw ScopeNotRegisteredException.scopeNotRegistered(scope);
    }
    existingScope.filter(s -> !forced)
                 .map(this::getMappedClients)
                 .filter(clients -> !CollectionUtils.isEmpty(clients))
                 .ifPresent(clients -> {
                   throw ScopeMappingException.existingClientDetailsMapping(scope, clients);
                 });
    existingScope.filter(s -> !forced)
                 .map(this::getMappedGroups)
                 .filter(groups -> !CollectionUtils.isEmpty(groups))
                 .ifPresent(groups -> {
                   throw ScopeMappingException.existingGroupMappings(scope, groups);
                 });
    if (forced) {
      StreamSupport.stream(scopeMappingRepository.findAll().spliterator(), false)
                   .filter(scopeMapping -> scopeMapping.getScopes().contains(scope))
                   .forEach(scopeMapping -> {
                     Set<String> scopes = scopeMapping.getScopes();
                     if (scopes.size() == 1) {
                       scopeMappingRepository.delete(scopeMapping);
                       return;
                     }

                     scopes.remove(scope);
                     scopeMapping.setScopes(scopes);
                     scopeMappingRepository.save(scopeMapping);
                   });
      StreamSupport.stream(redisClientDetailsRepository.findAll().spliterator(), false)
                   .filter(redisClientDetails -> redisClientDetails.getScope().contains(scope))
                   .forEach(redisClientDetails -> {
                     Set<String> scopes = redisClientDetails.getScope();
                     scopes.remove(scope);
                     redisClientDetails.setScopes(scopes);

                     Set<String> autoApprovedScopes = redisClientDetails.getAutoApprovedScopes();
                     if (CollectionUtils.containsInstance(autoApprovedScopes, scope) && !CollectionUtils.containsInstance(autoApprovedScopes, "true")) {
                       autoApprovedScopes.remove(scope);
                     }
                     autoApprovedScopes.remove(scope);
                     redisClientDetails.setAutoApprovedScopes(autoApprovedScopes);

                     redisClientDetailsRepository.save(redisClientDetails);
                   });
    }
    existingScope.ifPresent(scopeRepository::delete);
  }

  @Override
  public Set<String> getScopesOfGroup(@NotNull String group) throws MissingScopeMappingException {
    Optional<ScopeMapping> scopeMapping = scopeMappingRepository.findById(group);
    if (!scopeMapping.isPresent()) {
      throw new MissingScopeMappingException(group);
    }
    return scopeMapping.map(ScopeMapping::getScopes)
                       .orElseGet(HashSet::new);
  }

  @Override
  @Transactional
  public boolean saveScopeMapping(@NotNull String group, List<String> scopes) throws ScopeNotRegisteredException {
    checkForEmptyScopes(scopes);
    checkForInternalAdministrationScope(scopes);
    checkForUnregisteredScopes(scopes);

    final AtomicBoolean created = new AtomicBoolean(false);
    ScopeMapping scopeMapping =
        scopeMappingRepository.findById(group)
                              .orElseGet(() -> {
                                created.set(true);
                                return ScopeMapping.builder()
                                                   .group(group)
                                                   .build();
                              });
    scopeMapping.setScopes(new HashSet<>(scopes));
    scopeMappingRepository.save(scopeMapping);
    return created.get();
  }

  private void checkForEmptyScopes(List<String> scopes) {
    if (CollectionUtils.isEmpty(scopes)) {
      throw new EmptyScopesException();
    }
  }

  private void checkForInternalAdministrationScope(List<String> scopes) {
    if (scopes.stream()
              .anyMatch(AuthorizationServerConfiguration.INTERNAL_SCOPE::equals)) {
      throw new InternalAdministrationScopeNotAllowedException();
    }
  }

  private void checkForUnregisteredScopes(List<String> scopes) throws ScopeNotRegisteredException {
    final Set<String> existingScopes =
        StreamSupport.stream(scopeRepository.findAll().spliterator(), false)
                     .map(io.github.mufasa1976.spring.oauth2.authenticationserver.redis.model.Scope::getName)
                     .collect(Collectors.toSet());

    List<String> unregisteredScopes =
        scopes.stream()
              .filter(scope -> !existingScopes.contains(scope))
              .collect(Collectors.toList());
    if (!unregisteredScopes.isEmpty()) {
      throw ScopeNotRegisteredException.scopeNotRegistered(unregisteredScopes);
    }
  }

  @Override
  @Transactional
  public void deleteScopeMapping(@NotNull String group) throws MissingScopeMappingException {
    Optional<ScopeMapping> scopeMapping = scopeMappingRepository.findById(group);
    if (!scopeMapping.isPresent()) {
      throw new MissingScopeMappingException(group);
    }
    scopeMapping.ifPresent(scopeMappingRepository::delete);
  }
}
