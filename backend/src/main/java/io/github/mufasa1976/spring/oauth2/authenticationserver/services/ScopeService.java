package io.github.mufasa1976.spring.oauth2.authenticationserver.services;

import org.springframework.lang.Nullable;

import javax.validation.constraints.NotEmpty;
import javax.validation.constraints.NotNull;
import java.util.List;
import java.util.Optional;

public interface ScopeService {
  interface Scope {
    String getName();

    String getDescription();
  }

  List<Scope> getScopes();

  Optional<Scope> getScope(@NotNull String name);

  boolean saveScope(@NotNull String name, @Nullable String description);

  void deleteScope(@NotNull String scope);

  boolean saveScopeMapping(@NotNull String group, @NotEmpty List<String> scopes);
}
