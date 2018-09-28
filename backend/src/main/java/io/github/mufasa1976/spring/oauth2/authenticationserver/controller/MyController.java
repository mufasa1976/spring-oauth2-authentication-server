package io.github.mufasa1976.spring.oauth2.authenticationserver.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Optional;

@RestController
@RequestMapping("/api")
public class MyController {
  @GetMapping("/me")
  public String me() {
    return Optional.of(SecurityContextHolder.getContext())
                   .map(SecurityContext::getAuthentication)
                   .map(Authentication::getName)
                   .orElse("unknown");
  }

  @GetMapping("/not-found")
  public ResponseEntity notFound() {
    return ResponseEntity.notFound().build();
  }
}
