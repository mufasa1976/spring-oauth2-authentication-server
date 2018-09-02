package io.github.mufasa1976.spring.oauth2.authenticationserver.config;

import io.github.mufasa1976.spring.oauth2.authenticationserver.services.RedisClientDetailsManager;
import io.github.mufasa1976.spring.oauth2.authenticationserver.services.RedisClientDetailsServiceBuilder;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.Resource;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.token.*;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.store.JwtTokenStore;
import org.springframework.security.oauth2.provider.token.store.KeyStoreKeyFactory;

import javax.validation.constraints.NotNull;
import java.util.Arrays;

@Configuration
@RequiredArgsConstructor
@EnableAuthorizationServer
public class AuthorizationServerConfiguration extends AuthorizationServerConfigurerAdapter {
  public static final String INTERNAL_CLIENT_ID = "internal";

  private final PasswordEncoder passwordEncoder;
  private final AuthenticationManager authenticationManager;
  private final UserDetailsService userDetailsService;
  private final RedisClientDetailsManager clientDetailsManager;

  @NotNull
  @Value("${spring.security.oauth2.keystore}")
  private Resource keystore;

  @Value("${spring.security.oauth2.client-name:Internal Application}")
  private String internalClientName;

  @Override
  public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
    RedisClientDetailsServiceBuilder clientDetailsServiceBuilder = new RedisClientDetailsServiceBuilder(clientDetailsManager, internalClientName);
    clients.setBuilder(clientDetailsServiceBuilder);
    clientDetailsServiceBuilder.withClient(INTERNAL_CLIENT_ID)
                               .secret("internal")
                               .authorizedGrantTypes("authorization_code", "refresh_token", "password")
                               .redirectUris("http://localhost:8080/login/oauth2/code/internal")
                               .scopes("openid")
                               .autoApprove("true");
  }

  @Override
  public void configure(AuthorizationServerSecurityConfigurer security) throws Exception {
    security.passwordEncoder(passwordEncoder)
            .tokenKeyAccess("permitAll()")
            .checkTokenAccess("isAuthenticated()")
            .allowFormAuthenticationForClients();
  }

  @Override
  public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
    TokenEnhancerChain tokenEnhancerChain = new TokenEnhancerChain();
    tokenEnhancerChain.setTokenEnhancers(Arrays.asList(jwtAccessTokenConverter()));
    endpoints.tokenStore(tokenStore())
             .tokenEnhancer(tokenEnhancerChain)
             .authenticationManager(authenticationManager)
             .userDetailsService(userDetailsService);
  }

  @Bean
  public TokenStore tokenStore() {
    return new JwtTokenStore(jwtAccessTokenConverter());
  }

  @Bean
  public JwtAccessTokenConverter jwtAccessTokenConverter() {
    JwtAccessTokenConverter jwtAccessTokenConverter = new JwtAccessTokenConverter();
    jwtAccessTokenConverter.setAccessTokenConverter(accessTokenConverter());
    KeyStoreKeyFactory keystore = new KeyStoreKeyFactory(this.keystore, "changeIt".toCharArray());
    jwtAccessTokenConverter.setKeyPair(keystore.getKeyPair("jwk"));
    return jwtAccessTokenConverter;
  }

  private AccessTokenConverter accessTokenConverter() {
    DefaultAccessTokenConverter accessTokenConverter = new DefaultAccessTokenConverter();
    accessTokenConverter.setUserTokenConverter(userAuthenticationConverter());
    return accessTokenConverter;
  }

  private UserAuthenticationConverter userAuthenticationConverter() {
    MyUserAuthenticationConverter userAuthenticationConverter = new MyUserAuthenticationConverter();
    userAuthenticationConverter.setUserDetailsService(userDetailsService);
    return userAuthenticationConverter;
  }
}
