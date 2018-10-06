package io.github.mufasa1976.spring.oauth2.authenticationserver.exception;

import org.springframework.web.bind.annotation.ResponseStatus;

import java.util.Set;

import static org.springframework.http.HttpStatus.CONFLICT;

@ResponseStatus(CONFLICT)
public class ScopeMappingException extends RuntimeException {
  public static ScopeMappingException existingGroupMappings(String scope, Set<String> groups) {
    return new ScopeMappingException(String.format("Scope %s registered to Groups: %s", scope, groups));
  }

  public static ScopeMappingException existingClientDetailsMapping(String scope, Set<String> clients) {
    return new ScopeMappingException(String.format("Scope %s registered to Clients: %s", scope, clients));
  }

  private ScopeMappingException(String message) {
    super(message);
  }
}
