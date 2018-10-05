package io.github.mufasa1976.spring.oauth2.authenticationserver.controller;

import io.github.mufasa1976.spring.oauth2.authenticationserver.services.GroupService;
import io.github.mufasa1976.spring.oauth2.authenticationserver.services.ScopeService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import javax.validation.constraints.NotEmpty;
import java.util.List;

import static org.springframework.http.HttpStatus.CREATED;

@RestController
@RequiredArgsConstructor
public class GroupController {
  private final GroupService groupService;
  private final ScopeService scopeService;

  @GetMapping("/api/groups")
  public List<GroupService.Group> getGroups() {
    return groupService.getGroups();
  }

  @PutMapping("/api/groups/{group}/scopes")
  public ResponseEntity saveScopeMapping(@PathVariable("group") String group, @RequestBody @NotEmpty List<String> scopes) {
    if (scopeService.saveScopeMapping(group, scopes)) {
      return ResponseEntity.status(CREATED).build();
    }
    return ResponseEntity.ok().build();
  }

  @GetMapping("/api/unmapped-groups")
  public List<GroupService.Group> getUnmappedGroups() {
    return groupService.getUnmappedGroups();
  }
}
