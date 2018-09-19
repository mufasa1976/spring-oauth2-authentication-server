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
public class OAuthLoginController {
  private static final String LOGIN_DATA = "loginData";
  private static final String CLIENT_NAME = "clientName";

  private final RedisClientDetailsManager clientDetailsManager;

  @GetMapping("/oauth/login/redirect")
  public String redirectToLogin(
      @ModelAttribute OAuthLoginData oauthLoginData,
      @RequestParam Map<String, ?> requestParameter,
      RedirectAttributes redirectAttributes) {
    redirectAttributes.addFlashAttribute(LOGIN_DATA, oauthLoginData);
    if (requestParameter.containsKey("error")) {
      return "redirect:/oauth/login?error";
    }
    return "redirect:/oauth/login";
  }

  @GetMapping("/oauth/login")
  public ModelAndView showLogin(@ModelAttribute(LOGIN_DATA) Object loginData) {
    Map<String, Object> model = new HashMap<>();
    Optional.ofNullable(loginData)
            .filter(OAuthLoginData.class::isInstance)
            .map(OAuthLoginData.class::cast)
            .ifPresent(setLoginDataOn(model));
    return new ModelAndView("oauth/login", model);
  }

  private Consumer<OAuthLoginData> setLoginDataOn(Map<String, Object> model) {
    return OAuthLoginData -> {
      model.put(LOGIN_DATA, OAuthLoginData);
      clientDetailsManager.getClientByClientId(OAuthLoginData.getClient_id())
                          .map(RedisClientDetails::getClientName)
                          .ifPresent(clientName -> model.put(CLIENT_NAME, clientName));
    };
  }
}
