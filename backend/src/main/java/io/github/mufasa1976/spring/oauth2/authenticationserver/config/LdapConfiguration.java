package io.github.mufasa1976.spring.oauth2.authenticationserver.config;

import io.github.mufasa1976.spring.oauth2.authenticationserver.ldap.repository.GroupRepository;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.ldap.repository.config.EnableLdapRepositories;

@Configuration
@EnableLdapRepositories(basePackageClasses = GroupRepository.class)
public class LdapConfiguration {
}
