package io.github.mufasa1976.spring.oauth2.authenticationserver.redis.repositories;

import io.github.mufasa1976.spring.oauth2.authenticationserver.redis.model.LdapGroupToScopeMapping;
import org.springframework.data.repository.CrudRepository;

public interface LdapGroupToScopeMappingRepository extends CrudRepository<LdapGroupToScopeMapping, String> {}
