package io.github.mufasa1976.spring.oauth2.authenticationserver.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.servlet.ModelAndView;

import java.util.Collections;

@Controller
public class LoginController {
  @GetMapping("/login")
  public ModelAndView showLogin() {
    LoginData loginData = LoginData.builder()
                                   .build();
    return new ModelAndView("login", Collections.singletonMap("loginData", loginData));
  }
}
