package io.github.mufasa1976.spring.oauth2.authenticationserver.redis.repositories;

import io.github.mufasa1976.spring.oauth2.authenticationserver.redis.model.ScopeMapping;
import org.springframework.data.repository.CrudRepository;

public interface ScopeMappingRepository extends CrudRepository<ScopeMapping, String> {}
