package io.github.mufasa1976.spring.oauth2.authenticationserver.repositories;

import io.github.mufasa1976.spring.oauth2.authenticationserver.model.RedisClientDetails;
import org.springframework.data.repository.CrudRepository;

public interface ClientDetailsRepository extends CrudRepository<RedisClientDetails, String> {}
