package io.github.mufasa1976.spring.oauth2.authenticationserver.services;

import io.github.mufasa1976.spring.oauth2.authenticationserver.exception.MissingScopeMappingException;
import io.github.mufasa1976.spring.oauth2.authenticationserver.exception.ScopeNotRegisteredException;
import org.springframework.lang.Nullable;

import javax.validation.constraints.NotEmpty;
import javax.validation.constraints.NotNull;
import java.util.List;
import java.util.Optional;
import java.util.Set;

public interface ScopeService {
  interface Scope {
    String getName();

    String getDescription();

    Set<String> getMappedClients();

    Set<String> getMappedGroups();
  }

  List<Scope> getScopes();

  Optional<Scope> getScope(@NotNull String name);

  boolean saveScope(@NotNull String name, @Nullable String description);

  void deleteScope(@NotNull String scope, boolean forced) throws ScopeNotRegisteredException;

  Set<String> getScopesOfGroup(@NotNull String group) throws MissingScopeMappingException;

  boolean saveScopeMapping(@NotNull String group, List<String> scopes) throws ScopeNotRegisteredException;

  void deleteScopeMapping(@NotNull String group) throws MissingScopeMappingException;
}
