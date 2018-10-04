package io.github.mufasa1976.spring.oauth2.authenticationserver.redis.repositories;

import io.github.mufasa1976.spring.oauth2.authenticationserver.redis.model.Scope;
import org.springframework.data.repository.CrudRepository;

public interface ScopeRepository extends CrudRepository<Scope, String> {}
