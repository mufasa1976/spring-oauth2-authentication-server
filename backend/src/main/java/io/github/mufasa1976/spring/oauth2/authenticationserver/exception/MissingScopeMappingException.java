package io.github.mufasa1976.spring.oauth2.authenticationserver.exception;

public class MissingScopeMappingException extends Exception {
  public MissingScopeMappingException(String group) {
    super("Group " + group + " hasn't any mapped Scope");
  }
}
