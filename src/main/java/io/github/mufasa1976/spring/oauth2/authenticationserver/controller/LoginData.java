package io.github.mufasa1976.spring.oauth2.authenticationserver.controller;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import static lombok.AccessLevel.PRIVATE;

@Data
@NoArgsConstructor
@AllArgsConstructor(access = PRIVATE)
@Builder
public class LoginData {
  private String response_type;
  private String client_id;
  private String scope;
  private String redirect_uri;
  private String username;
  private String password;
  private String state;
}
