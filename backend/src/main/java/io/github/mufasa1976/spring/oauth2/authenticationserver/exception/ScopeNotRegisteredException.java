package io.github.mufasa1976.spring.oauth2.authenticationserver.exception;

import javax.validation.constraints.NotEmpty;
import java.util.*;

public class ScopeNotRegisteredException extends Exception {
  public static ScopeNotRegisteredException scopeNotRegistered(String scope, String... scopes) {
    List<String> scopeList = new ArrayList<>();
    scopeList.add(scope);
    scopeList.addAll(Arrays.asList(scopes));
    return scopeNotRegistered(scopeList);
  }

  public static ScopeNotRegisteredException scopeNotRegistered(@NotEmpty Collection<String> scopes) {
    return new ScopeNotRegisteredException("Scopes " + scopes.stream().reduce((left, right) -> left + ", " + right) + " not registered", scopes);
  }

  private final Collection<String> scopes;

  private ScopeNotRegisteredException(String message, Collection<String> scopes) {
    super(message);
    this.scopes = scopes;
  }

  public Collection<String> getScopes() {
    return Collections.unmodifiableCollection(scopes);
  }
}
