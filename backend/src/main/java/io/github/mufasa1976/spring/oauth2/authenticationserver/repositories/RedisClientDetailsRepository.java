package io.github.mufasa1976.spring.oauth2.authenticationserver.repositories;

import io.github.mufasa1976.spring.oauth2.authenticationserver.model.RedisClientDetails;
import org.springframework.data.repository.CrudRepository;

public interface RedisClientDetailsRepository extends CrudRepository<RedisClientDetails, String> {}
