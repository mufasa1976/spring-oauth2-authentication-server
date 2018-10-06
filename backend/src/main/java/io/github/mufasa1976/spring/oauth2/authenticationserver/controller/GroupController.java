package io.github.mufasa1976.spring.oauth2.authenticationserver.controller;

import io.github.mufasa1976.spring.oauth2.authenticationserver.exception.MissingScopeMappingException;
import io.github.mufasa1976.spring.oauth2.authenticationserver.exception.ScopeNotRegisteredException;
import io.github.mufasa1976.spring.oauth2.authenticationserver.services.GroupService;
import io.github.mufasa1976.spring.oauth2.authenticationserver.services.ScopeService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;

import javax.validation.constraints.NotEmpty;
import java.util.Comparator;
import java.util.List;
import java.util.Set;

import static org.springframework.http.HttpStatus.CREATED;
import static org.springframework.http.HttpStatus.NOT_FOUND;

@RestController
@RequiredArgsConstructor
public class GroupController {
  private final GroupService groupService;
  private final ScopeService scopeService;

  @GetMapping("/api/groups")
  public List<GroupService.Group> getGroups() {
    List<GroupService.Group> groups = groupService.getGroups();
    groups.sort(Comparator.comparing(GroupService.Group::getName));
    return groups;
  }

  @GetMapping("/api/groups/{group}/scopes")
  public ResponseEntity<Set<String>> getScopesOfGroup(@PathVariable("group") String group) {
    try {
      return ResponseEntity.ok(scopeService.getScopesOfGroup(group));
    } catch (MissingScopeMappingException e) {
      return ResponseEntity.notFound().build();
    }
  }

  @PutMapping("/api/groups/{group}/scopes")
  public ResponseEntity saveScopeMapping(@PathVariable("group") String group, @RequestBody List<String> scopes) {
    try {
      if (scopeService.saveScopeMapping(group, scopes)) {
        return ResponseEntity.status(CREATED).build();
      }
    } catch (ScopeNotRegisteredException e) {
      return ResponseEntity.status(NOT_FOUND)
                           .body(e.getScopes());
    }
    return ResponseEntity.ok().build();
  }

  @DeleteMapping("/api/groups/{group}/scopes")
  public ResponseEntity deleteScopeMapping(@PathVariable("group") String group) {
    try {
      scopeService.deleteScopeMapping(group);
    } catch (MissingScopeMappingException e) {
      return ResponseEntity.notFound().build();
    }
    return ResponseEntity.noContent().build();
  }

  @GetMapping("/api/unmapped-groups")
  public List<GroupService.Group> getUnmappedGroups() {
    return groupService.getUnmappedGroups();
  }
}
