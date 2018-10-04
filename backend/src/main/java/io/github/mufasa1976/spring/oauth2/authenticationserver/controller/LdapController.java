package io.github.mufasa1976.spring.oauth2.authenticationserver.controller;

import io.github.mufasa1976.spring.oauth2.authenticationserver.ldap.model.Group;
import io.github.mufasa1976.spring.oauth2.authenticationserver.ldap.repository.GroupRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.StreamSupport;

@RestController
@RequiredArgsConstructor
@RequestMapping("/api/ldap")
public class LdapController {
  private final GroupRepository groupRepository;

  @GetMapping("/groups")
  public List<String> getGroups() {
    return StreamSupport.stream(groupRepository.findAll().spliterator(), false)
                        .map(Group::getName)
                        .collect(Collectors.toList());
  }
}
