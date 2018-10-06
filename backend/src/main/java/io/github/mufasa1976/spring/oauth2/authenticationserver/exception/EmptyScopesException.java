package io.github.mufasa1976.spring.oauth2.authenticationserver.exception;

import org.springframework.web.bind.annotation.ResponseStatus;

import static org.springframework.http.HttpStatus.BAD_REQUEST;

@ResponseStatus(BAD_REQUEST)
public class EmptyScopesException extends RuntimeException {
  public EmptyScopesException() {
    super("No Scopes defined");
  }
}
