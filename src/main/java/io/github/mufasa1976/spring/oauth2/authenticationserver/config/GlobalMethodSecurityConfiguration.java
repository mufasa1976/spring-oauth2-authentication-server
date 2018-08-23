package io.github.mufasa1976.spring.oauth2.authenticationserver.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.expression.method.MethodSecurityExpressionHandler;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.provider.expression.OAuth2MethodSecurityExpressionHandler;

@Configuration
@EnableGlobalMethodSecurity(securedEnabled = true, prePostEnabled = true)
public class GlobalMethodSecurityConfiguration
    extends org.springframework.security.config.annotation.method.configuration.GlobalMethodSecurityConfiguration {

  @Bean
  public MethodSecurityExpressionHandler oauth2MethodSecurityExpressionHandler() {
    return new OAuth2MethodSecurityExpressionHandler();
  }
}
