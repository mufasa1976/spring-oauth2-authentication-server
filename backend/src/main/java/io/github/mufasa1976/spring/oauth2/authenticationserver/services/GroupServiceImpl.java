package io.github.mufasa1976.spring.oauth2.authenticationserver.services;

import io.github.mufasa1976.spring.oauth2.authenticationserver.ApplicationProperties;
import io.github.mufasa1976.spring.oauth2.authenticationserver.exception.MissingScopeMappingException;
import io.github.mufasa1976.spring.oauth2.authenticationserver.ldap.repository.GroupRepository;
import io.github.mufasa1976.spring.oauth2.authenticationserver.redis.model.ScopeMapping;
import io.github.mufasa1976.spring.oauth2.authenticationserver.redis.repositories.ScopeMappingRepository;
import lombok.Builder;
import lombok.RequiredArgsConstructor;
import lombok.Value;
import org.springframework.ldap.query.LdapQuery;
import org.springframework.ldap.query.LdapQueryBuilder;
import org.springframework.stereotype.Service;

import javax.validation.constraints.NotNull;
import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.StreamSupport;

@Service
@RequiredArgsConstructor
public class GroupServiceImpl implements GroupService {
  private final GroupRepository groupRepository;
  private final ScopeMappingRepository scopeMappingRepository;
  private final ApplicationProperties applicationProperties;

  @org.springframework.beans.factory.annotation.Value("${spring.ldap.base}")
  private String baseDN;

  @Value
  @Builder
  private final static class GroupImpl implements Group {
    private String name;
    private String description;
  }

  @Override
  public List<GroupService.Group> getGroups() {
    return StreamSupport.stream(groupRepository.findAll(getGroupFilter()).spliterator(), false)
                        .map(group -> GroupImpl.builder()
                                               .name(group.getName())
                                               .description(group.getDescription())
                                               .build())
                        .collect(Collectors.toList());
  }

  private LdapQuery getGroupFilter() {
    return LdapQueryBuilder.query()
                           .base(baseDN)
                           .filter(applicationProperties.getLdapGroupFilter());
  }


  @Override
  public List<GroupService.Group> getUnmappedGroups() {
    Set<String> mappedGroups =
        StreamSupport.stream(scopeMappingRepository.findAll().spliterator(), false)
                     .map(ScopeMapping::getGroup)
                     .collect(Collectors.toSet());
    return StreamSupport.stream(groupRepository.findAll(getGroupFilter()).spliterator(), false)
                        .filter(group -> !mappedGroups.contains(group.getName()))
                        .map(group -> GroupImpl.builder()
                                               .name(group.getName())
                                               .description(group.getDescription())
                                               .build())
                        .collect(Collectors.toList());
  }
}
