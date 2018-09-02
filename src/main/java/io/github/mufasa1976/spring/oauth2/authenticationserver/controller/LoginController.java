package io.github.mufasa1976.spring.oauth2.authenticationserver.controller;

import io.github.mufasa1976.spring.oauth2.authenticationserver.model.RedisClientDetails;
import io.github.mufasa1976.spring.oauth2.authenticationserver.services.RedisClientDetailsManager;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.ModelAndView;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.function.Consumer;

@Controller
@RequiredArgsConstructor
public class LoginController {
  private static final String LOGIN_DATA = "loginData";
  private static final String CLIENT_NAME = "clientName";

  private final RedisClientDetailsManager clientDetailsManager;

  @GetMapping("/oauth/login/redirect")
  public String redirectToLogin(
      @ModelAttribute LoginData loginData,
      @RequestParam Map<String, ?> requestParameter,
      RedirectAttributes redirectAttributes) {
    redirectAttributes.addFlashAttribute(LOGIN_DATA, loginData);
    if (requestParameter.containsKey("error")) {
      return "redirect:/oauth/login?error";
    }
    return "redirect:/oauth/login";
  }

  @GetMapping("/oauth/login")
  public ModelAndView showLogin(@ModelAttribute(LOGIN_DATA) Object loginData) {
    Map<String, Object> model = new HashMap<>();
    Optional.ofNullable(loginData)
            .filter(LoginData.class::isInstance)
            .map(LoginData.class::cast)
            .ifPresent(setLoginDataOn(model));
    return new ModelAndView("login", model);
  }

  private Consumer<LoginData> setLoginDataOn(Map<String, Object> model) {
    return loginData -> {
      model.put(LOGIN_DATA, loginData);
      clientDetailsManager.getClientByClientId(loginData.getClient_id())
                          .map(RedisClientDetails::getClientName)
                          .ifPresent(clientName -> model.put(CLIENT_NAME, clientName));
    };
  }
}
