package io.github.mufasa1976.spring.oauth2.authenticationserver.controller;

import io.github.mufasa1976.spring.oauth2.authenticationserver.exception.ScopeNotRegisteredException;
import io.github.mufasa1976.spring.oauth2.authenticationserver.services.ScopeService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;

import java.util.Comparator;
import java.util.List;

import static org.springframework.http.HttpStatus.CREATED;

@RestController
@RequiredArgsConstructor
public class ScopeController {
  private final ScopeService scopeService;

  @GetMapping("/api/scopes")
  public List<ScopeService.Scope> getScopes() {
    List<ScopeService.Scope> scopes = scopeService.getScopes();
    scopes.sort(Comparator.comparing(ScopeService.Scope::getName));
    return scopes;
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
  public ResponseEntity deleteScope(@PathVariable("scope") String scope, @RequestParam(value = "forced", defaultValue = "false") boolean forced) {
    try {
      scopeService.deleteScope(scope, forced);
    } catch (ScopeNotRegisteredException e) {
      return ResponseEntity.notFound().build();
    }
    return ResponseEntity.noContent().build();
  }
}
