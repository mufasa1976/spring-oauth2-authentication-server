package io.github.mufasa1976.spring.oauth2.authenticationserver.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.data.redis.RedisProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.connection.RedisConnectionFactory;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.repository.configuration.EnableRedisRepositories;
import org.springframework.data.redis.serializer.GenericJackson2JsonRedisSerializer;
import org.springframework.data.redis.serializer.StringRedisSerializer;
import redis.embedded.RedisServer;

import javax.annotation.PostConstruct;
import javax.annotation.PreDestroy;

@Configuration
@EnableRedisRepositories
public class RedisConfiguration {
  @Bean
  public RedisTemplate<String, Object> redisTemplate(RedisConnectionFactory connectionFactory, ObjectMapper objectMapper) {
    RedisTemplate<String, Object> redisTemplate = new RedisTemplate<>();
    redisTemplate.setConnectionFactory(connectionFactory);
    redisTemplate.setKeySerializer(new StringRedisSerializer());
    redisTemplate.setValueSerializer(new GenericJackson2JsonRedisSerializer(objectMapper));
    return redisTemplate;
  }

  @Bean
  public StringRedisTemplate stringRedisTemplate(RedisConnectionFactory connectionFactory) {
    StringRedisTemplate redisTemplate = new StringRedisTemplate();
    redisTemplate.setConnectionFactory(connectionFactory);
    return redisTemplate;
  }

  @Bean
  @ConditionalOnProperty(prefix = "spring.redis.embedded", name = "enabled", havingValue = "true")
  public EmbeddedRedis embeddedRedis(RedisProperties redisProperties) {
    return new EmbeddedRedis(redisProperties);
  }

  @RequiredArgsConstructor
  public static class EmbeddedRedis {
    private final RedisProperties properties;

    private RedisServer redisServer;

    @PostConstruct
    public void startRedis() throws Exception {
      redisServer = new RedisServer(properties.getPort());
      redisServer.start();
    }

    @PreDestroy
    public void stopRedis() throws Exception {
      redisServer.stop();
    }
  }

}
