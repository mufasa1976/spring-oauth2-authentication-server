package io.github.mufasa1976.spring.oauth2.authenticationserver.ldap.repository;

import io.github.mufasa1976.spring.oauth2.authenticationserver.ldap.model.Group;
import org.springframework.data.ldap.repository.LdapRepository;

public interface GroupRepository extends LdapRepository<Group> {}
