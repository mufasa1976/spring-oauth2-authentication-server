package io.github.mufasa1976.spring.oauth2.authenticationserver.controller;

import io.github.mufasa1976.spring.oauth2.authenticationserver.services.ScopeService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import javax.validation.constraints.NotEmpty;
import java.util.List;

import static org.springframework.http.HttpStatus.CREATED;

@RestController
@RequiredArgsConstructor
public class ScopeController {
  private final ScopeService scopeService;

  @GetMapping("/api/scopes")
  public List<ScopeService.Scope> getScopes() {
    return scopeService.getScopes();
  }

  @GetMapping("/api/scopes/{scope}")
  public ResponseEntity<ScopeService.Scope> getScope(@PathVariable("scope") String scope) {
    return scopeService.getScope(scope)
                       .map(ResponseEntity::ok)
                       .orElseGet(ResponseEntity.notFound()::build);
  }

  @PutMapping("/api/scopes/{scope}")
  public ResponseEntity saveScope(@PathVariable("scope") String scope, @RequestBody String description) {
    if (scopeService.saveScope(scope, description)) {
      return ResponseEntity.status(CREATED).build();
    }
    return ResponseEntity.ok().build();
  }

  @DeleteMapping("/api/scopes/{scope}")
  public void deleteScope(@PathVariable("scope") String scope) {
    scopeService.deleteScope(scope);
  }
}
