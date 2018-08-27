package io.github.mufasa1976.spring.oauth2.authenticationserver.controller;

import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class LoginData {
  private String client_id;
  private String scope;
  private String redirectUri;
  private String username;
  private String password;
}
