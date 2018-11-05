package io.github.mufasa1976.spring.oauth2.authenticationserver.config;

import io.github.mufasa1976.spring.oauth2.authenticationserver.ApplicationProperties;
import io.github.mufasa1976.spring.oauth2.authenticationserver.services.RedisClientDetailsManager;
import io.github.mufasa1976.spring.oauth2.authenticationserver.services.RedisClientDetailsServiceBuilder;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.common.util.OAuth2Utils;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.*;
import org.springframework.security.oauth2.provider.request.DefaultOAuth2RequestFactory;
import org.springframework.security.oauth2.provider.token.AccessTokenConverter;
import org.springframework.security.oauth2.provider.token.DefaultAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.UserAuthenticationConverter;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.store.JwtTokenStore;
import org.springframework.security.oauth2.provider.token.store.KeyStoreKeyFactory;

import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;

@Configuration
@RequiredArgsConstructor
@EnableAuthorizationServer
public class AuthorizationServerConfiguration extends AuthorizationServerConfigurerAdapter {
  public static final String INTERNAL_CLIENT_ID = "internal";
  public static final String INTERNAL_SCOPE = "internal_administration";

  private final PasswordEncoder passwordEncoder;
  private final AuthenticationManager authenticationManager;
  private final UserDetailsService userDetailsService;
  private final RedisClientDetailsManager clientDetailsManager;
  private final ApplicationProperties properties;

  @Override
  public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
    RedisClientDetailsServiceBuilder clientDetailsServiceBuilder = new RedisClientDetailsServiceBuilder(clientDetailsManager, properties.getClientName());
    clients.setBuilder(clientDetailsServiceBuilder);
    clientDetailsServiceBuilder.withClient(INTERNAL_CLIENT_ID)
                               .authorizedGrantTypes("password", "refresh_token")
                               .scopes(INTERNAL_SCOPE)
                               .authorities(INTERNAL_SCOPE)
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
    endpoints.tokenStore(tokenStore())
             .accessTokenConverter(jwtAccessTokenConverter())
             .authenticationManager(authenticationManager)
             .userDetailsService(userDetailsService)
             .requestFactory(oauth2RequestFactory(endpoints.getClientDetailsService()));
  }

  @Bean
  public TokenStore tokenStore() {
    return new JwtTokenStore(jwtAccessTokenConverter());
  }

  @Bean
  public JwtAccessTokenConverter jwtAccessTokenConverter() {
    JwtAccessTokenConverter jwtAccessTokenConverter = new JwtAccessTokenConverter();
    jwtAccessTokenConverter.setAccessTokenConverter(accessTokenConverter());
    KeyStoreKeyFactory keystore = new KeyStoreKeyFactory(properties.getKeystore(), "changeIt".toCharArray());
    jwtAccessTokenConverter.setKeyPair(keystore.getKeyPair("jwt"));
    return jwtAccessTokenConverter;
  }

  private AccessTokenConverter accessTokenConverter() {
    DefaultAccessTokenConverter accessTokenConverter = new DefaultAccessTokenConverter();
    accessTokenConverter.setUserTokenConverter(userAuthenticationConverter());
    return accessTokenConverter;
  }

  private UserAuthenticationConverter userAuthenticationConverter() {
    LdapUserAuthenticationConverter userAuthenticationConverter = new LdapUserAuthenticationConverter();
    userAuthenticationConverter.setUserDetailsService(userDetailsService);
    return userAuthenticationConverter;
  }

  @Bean
  public OAuth2RequestFactory oauth2RequestFactory(ClientDetailsService clientDetailsService) {
    if (!properties.isCheckUserScope()) {
      return new DefaultOAuth2RequestFactory(clientDetailsService);
    }

    DefaultOAuth2RequestFactory requestFactory = new DefaultOAuth2RequestFactory(clientDetailsService) {
      private SecurityContextAccessor securityContextAccessor = new DefaultSecurityContextAccessor();

      @Override
      public void setSecurityContextAccessor(SecurityContextAccessor securityContextAccessor) {
        super.setSecurityContextAccessor(securityContextAccessor);
        this.securityContextAccessor = securityContextAccessor;
      }

      @Override
      public AuthorizationRequest createAuthorizationRequest(Map<String, String> authorizationParameters) {
        AuthorizationRequest authorizationRequest = super.createAuthorizationRequest(authorizationParameters);

        if (securityContextAccessor.isUser()) {
          authorizationRequest.setAuthorities(securityContextAccessor.getAuthorities());
        }

        return authorizationRequest;
      }
    };
    requestFactory.setCheckUserScopes(true);
    return requestFactory;
  }
}
