package io.github.mufasa1976.spring.oauth2.authenticationserver.redis.repositories;

import io.github.mufasa1976.spring.oauth2.authenticationserver.redis.model.RedisClientDetails;
import org.springframework.data.repository.CrudRepository;

public interface RedisClientDetailsRepository extends CrudRepository<RedisClientDetails, String> {}
