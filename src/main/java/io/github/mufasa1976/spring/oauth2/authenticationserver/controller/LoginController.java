package io.github.mufasa1976.spring.oauth2.authenticationserver.controller;

import lombok.RequiredArgsConstructor;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.ModelAndView;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

@Controller
@RequiredArgsConstructor
public class LoginController {
  private static final String MODEL = "loginData";

  private final ClientDetailsService clientDetailsService;

  @GetMapping("/login/redirect")
  public String redirectToLogin(
      @ModelAttribute LoginData loginData,
      @RequestParam Map<String, ?> requestParameter,
      RedirectAttributes redirectAttributes) {
    redirectAttributes.addFlashAttribute(MODEL, loginData);
    if (requestParameter.containsKey("error")) {
      return "redirect:/login?error";
    }
    return "redirect:/login";
  }

  @GetMapping("/login")
  public ModelAndView showLogin(@ModelAttribute(MODEL) Object loginData) {
    Map<String, Object> model = new HashMap<>();
    Optional.ofNullable(loginData)
            .filter(LoginData.class::isInstance)
            .map(LoginData.class::cast)
            .ifPresent(ld -> model.put("loginData", ld));
    return new ModelAndView("login", model);
  }
}
