package io.github.mufasa1976.spring.oauth2.authenticationserver.exception;

import org.springframework.web.bind.annotation.ResponseStatus;

import javax.validation.constraints.NotEmpty;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;

import static org.springframework.http.HttpStatus.NOT_FOUND;

@ResponseStatus(NOT_FOUND)
public class ScopeNotRegisteredException extends RuntimeException {
  public static ScopeNotRegisteredException scopeNotRegistered(String scope, String... scopes) {
    List<String> scopeList = new ArrayList<>();
    scopeList.add(scope);
    scopeList.addAll(Arrays.asList(scopes));
    return scopeNotRegistered(scopeList);
  }

  public static ScopeNotRegisteredException scopeNotRegistered(@NotEmpty Collection<String> scopes) {
    return new ScopeNotRegisteredException("Scopes " + scopes.stream().reduce((left, right) -> left + ", " + right) + " not registered");
  }

  private ScopeNotRegisteredException(String message) {
    super(message);
  }
}
