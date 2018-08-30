package io.github.mufasa1976.spring.oauth2.authenticationserver.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.ModelAndView;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import java.util.Collections;
import java.util.Map;

@Controller
public class LoginController {
  private static final String MODEL = "loginData";

  @GetMapping("/redirectToLogin")
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
    return new ModelAndView("login", Collections.singletonMap("loginData", loginData == null ? null : (LoginData) loginData));
  }
}
