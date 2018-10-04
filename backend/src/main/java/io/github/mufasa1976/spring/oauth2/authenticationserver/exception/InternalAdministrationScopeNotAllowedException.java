package io.github.mufasa1976.spring.oauth2.authenticationserver.exception;

import io.github.mufasa1976.spring.oauth2.authenticationserver.config.AuthorizationServerConfiguration;
import org.springframework.web.bind.annotation.ResponseStatus;

import static org.springframework.http.HttpStatus.CONFLICT;

@ResponseStatus(CONFLICT)
public class InternalAdministrationScopeNotAllowedException extends RuntimeException {
  public InternalAdministrationScopeNotAllowedException() {
    super("Scope " + AuthorizationServerConfiguration.INTERNAL_SCOPE + " not allowed");
  }
}
