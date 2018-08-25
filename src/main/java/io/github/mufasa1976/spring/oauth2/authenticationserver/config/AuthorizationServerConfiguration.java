package io.github.mufasa1976.spring.oauth2.authenticationserver.config;

import lombok.NoArgsConstructor;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.ldap.userdetails.InetOrgPerson;
import org.springframework.security.ldap.userdetails.Person;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.token.DefaultAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.DefaultUserAuthenticationConverter;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.store.JwtTokenStore;

import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.function.Function;

@Configuration
@RequiredArgsConstructor
@EnableAuthorizationServer
public class AuthorizationServerConfiguration extends AuthorizationServerConfigurerAdapter {
  private final PasswordEncoder passwordEncoder;
  private final AuthenticationManager authenticationManager;
  private final UserDetailsService userDetailsService;

  @Override
  public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
    clients.inMemory()
           .withClient("my-server-frontend")
           .secret(passwordEncoder.encode("s3cr3t"))
           .authorizedGrantTypes("authorization_code", "client_credentials", "implicit", "password", "refresh_token")
           .redirectUris("http://localhost:8080/index.html")
           .autoApprove("true");
  }

  @Override
  public void configure(AuthorizationServerSecurityConfigurer security) throws Exception {
    security.passwordEncoder(passwordEncoder)
            .tokenKeyAccess("permitAll()")
            .checkTokenAccess("isAuthenticated()");
  }

  @Override
  public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
    endpoints.tokenStore(tokenStore())
             .accessTokenConverter(accessTokenConverter())
             .authenticationManager(authenticationManager)
             .userDetailsService(userDetailsService);
  }

  @Bean
  public TokenStore tokenStore() {
    return new JwtTokenStore(accessTokenConverter());
  }

  @Bean
  public JwtAccessTokenConverter accessTokenConverter() {
    JwtAccessTokenConverter jwtAccessTokenConverter = new JwtAccessTokenConverter();
    jwtAccessTokenConverter.setSigningKey("secret123");
    DefaultAccessTokenConverter accessTokenConverter = new DefaultAccessTokenConverter();
    MyUserAuthenticationConverter userAuthenticationConverter = new MyUserAuthenticationConverter();
    userAuthenticationConverter.setUserDetailsService(userDetailsService);
    accessTokenConverter.setUserTokenConverter(userAuthenticationConverter);
    jwtAccessTokenConverter.setAccessTokenConverter(accessTokenConverter);
    return jwtAccessTokenConverter;
  }

  @NoArgsConstructor
  private static class MyUserAuthenticationConverter extends DefaultUserAuthenticationConverter {

    @Override
    public Map<String, ?> convertUserAuthentication(Authentication authentication) {
      Map<String, Object> attributes = new HashMap<>(super.convertUserAuthentication(authentication));
      if (authentication.getPrincipal() instanceof Person) {
        Person person = (Person) authentication.getPrincipal();
        setAttribute(person, attributes, Person::getSn, "lastName");
        setAttribute(person, attributes, Person::getGivenName, "firstName");
      }
      if (authentication.getPrincipal() instanceof InetOrgPerson) {
        InetOrgPerson inetOrgPerson = (InetOrgPerson) authentication.getPrincipal();
        setAttribute(inetOrgPerson, attributes, InetOrgPerson::getDisplayName, "displayName");
        setAttribute(inetOrgPerson, attributes, InetOrgPerson::getMail, "mail");
      }
      return attributes;
    }

    private <T extends Person> void setAttribute(T person, Map<String, Object> attributes, Function<T, Object> extractor, String attributeName) {
      Optional.of(person)
              .map(extractor)
              .ifPresent(value -> attributes.put(attributeName, value));
    }
  }
}
