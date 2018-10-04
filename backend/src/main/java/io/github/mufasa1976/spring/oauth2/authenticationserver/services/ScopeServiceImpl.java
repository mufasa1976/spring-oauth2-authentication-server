package io.github.mufasa1976.spring.oauth2.authenticationserver.services;

import io.github.mufasa1976.spring.oauth2.authenticationserver.config.AuthorizationServerConfiguration;
import io.github.mufasa1976.spring.oauth2.authenticationserver.exception.InternalAdministrationScopeNotAllowedException;
import io.github.mufasa1976.spring.oauth2.authenticationserver.exception.ScopeNotRegisteredException;
import io.github.mufasa1976.spring.oauth2.authenticationserver.ldap.repository.GroupRepository;
import io.github.mufasa1976.spring.oauth2.authenticationserver.redis.model.ScopeMapping;
import io.github.mufasa1976.spring.oauth2.authenticationserver.redis.repositories.ScopeMappingRepository;
import io.github.mufasa1976.spring.oauth2.authenticationserver.redis.repositories.ScopeRepository;
import lombok.Builder;
import lombok.RequiredArgsConstructor;
import lombok.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import javax.validation.constraints.NotEmpty;
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
  private final GroupRepository groupRepository;
  private final ScopeMappingRepository scopeMappingRepository;
  private final ScopeRepository scopeRepository;

  @Value
  @Builder
  private final static class GroupImpl implements ScopeService.Group {
    private String name;
    private String description;
  }

  @Value
  @Builder
  private final static class ScopeImpl implements Scope {
    private String name;
    private String description;
  }

  @Override
  public List<ScopeService.Group> getGroups() {
    return StreamSupport.stream(groupRepository.findAll().spliterator(), false)
                        .map(group -> GroupImpl.builder()
                                               .name(group.getName())
                                               .description(group.getDescription())
                                               .build())
                        .collect(Collectors.toList());
  }

  @Override
  public List<Scope> getScopes() {
    return StreamSupport.stream(scopeRepository.findAll().spliterator(), false)
                        .map(scope -> ScopeImpl.builder()
                                               .name(scope.getName())
                                               .description(scope.getDescription())
                                               .build())
                        .collect(Collectors.toList());
  }

  @Override
  public Optional<Scope> getScope(@NotNull String name) {
    return scopeRepository.findById(name)
                          .map(scope -> ScopeImpl.builder()
                                                 .name(scope.getName())
                                                 .description(scope.getDescription())
                                                 .build());
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
  public void deleteScope(@NotNull String scope) {
    Optional<io.github.mufasa1976.spring.oauth2.authenticationserver.redis.model.Scope> existingScope = scopeRepository.findById(scope);
    if (!existingScope.isPresent()) {
      throw ScopeNotRegisteredException.scopeNotRegistered(scope);
    }
    existingScope.ifPresent(scopeRepository::delete);
  }

  @Override
  @Transactional
  public boolean saveScopeMapping(@NotNull String group, @NotEmpty List<String> scopes) {
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

  private void checkForInternalAdministrationScope(@NotEmpty List<String> scopes) {
    if (scopes.stream()
              .anyMatch(AuthorizationServerConfiguration.INTERNAL_SCOPE::equals)) {
      throw new InternalAdministrationScopeNotAllowedException();
    }
  }

  private void checkForUnregisteredScopes(@NotEmpty List<String> scopes) {
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
}
