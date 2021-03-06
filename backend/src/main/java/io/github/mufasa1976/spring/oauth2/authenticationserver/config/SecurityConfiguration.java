package io.github.mufasa1976.spring.oauth2.authenticationserver.config;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.core.env.Environment;
import org.springframework.ldap.core.ContextSource;
import org.springframework.ldap.core.support.LdapContextSource;
import org.springframework.security.access.expression.method.MethodSecurityExpressionHandler;
import org.springframework.security.authentication.AuthenticationDetailsSource;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.ldap.search.FilterBasedLdapUserSearch;
import org.springframework.security.ldap.search.LdapUserSearch;
import org.springframework.security.ldap.userdetails.DefaultLdapAuthoritiesPopulator;
import org.springframework.security.ldap.userdetails.InetOrgPersonContextMapper;
import org.springframework.security.ldap.userdetails.LdapAuthoritiesPopulator;
import org.springframework.security.ldap.userdetails.LdapUserDetailsService;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.ResourceServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configurers.ResourceServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.OAuth2Request;
import org.springframework.security.oauth2.provider.OAuth2RequestFactory;
import org.springframework.security.oauth2.provider.endpoint.TokenEndpointAuthenticationFilter;
import org.springframework.security.oauth2.provider.expression.OAuth2MethodSecurityExpressionHandler;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.util.StringUtils;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;
import org.springframework.web.util.UriComponentsBuilder;

import javax.servlet.Filter;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Arrays;
import java.util.stream.Stream;

import static org.springframework.security.config.http.SessionCreationPolicy.IF_REQUIRED;
import static org.springframework.security.oauth2.common.util.OAuth2Utils.*;

@Configuration
@RequiredArgsConstructor
@EnableWebSecurity
@Slf4j
public class SecurityConfiguration {
  @Bean
  public PasswordEncoder passwordEncoder() {
    return PasswordEncoderFactories.createDelegatingPasswordEncoder();
  }

  @Configuration
  @EnableGlobalMethodSecurity(securedEnabled = true, prePostEnabled = true)
  public class GlobalMethodSecurityConfiguration extends org.springframework.security.config.annotation.method.configuration.GlobalMethodSecurityConfiguration {
    @Bean
    public MethodSecurityExpressionHandler oauth2MethodSecurityExpressionHandler() {
      return new OAuth2MethodSecurityExpressionHandler();
    }
  }

  @Configuration
  @Order(1)
  public class AuthorizationServerSecurityConfiguration extends WebSecurityConfigurerAdapter {
    private final ContextSource contextSource;
    private final ScopedInetOrgPersonContextMapper scopedInetOrgPersonContextMapper;

    @Value("${spring.ldap.base}")
    private String baseDN;

    private final boolean debug;

    public AuthorizationServerSecurityConfiguration(ContextSource contextSource, ScopedInetOrgPersonContextMapper scopedInetOrgPersonContextMapper, Environment environment) {
      super(true);
      this.contextSource = contextSource;
      this.scopedInetOrgPersonContextMapper = scopedInetOrgPersonContextMapper;
      this.debug = environment.getProperty("debug") != null && !"false".equals(environment.getProperty("debug"));
    }

    @Bean
    @Override
    public AuthenticationManager authenticationManagerBean() throws Exception {
      return super.authenticationManagerBean();
    }

    @Bean
    @ConditionalOnProperty(prefix = "oauth2-server", name = "check-user-scope")
    public Filter tokenEndpointAuthenticationFilter(OAuth2RequestFactory oauth2RequestFactory) throws Exception {
      TokenEndpointAuthenticationFilter tokenEndpointAuthenticationFilter = new TokenEndpointAuthenticationFilter(authenticationManagerBean(), oauth2RequestFactory) {
        private AuthenticationDetailsSource<HttpServletRequest, ?> authenticationDetailsSource;

        @Override
        public void setAuthenticationDetailsSource(AuthenticationDetailsSource<HttpServletRequest, ?> authenticationDetailsSource) {
          super.setAuthenticationDetailsSource(authenticationDetailsSource);
          this.authenticationDetailsSource = authenticationDetailsSource;
        }

        @Override
        protected Authentication extractCredentials(HttpServletRequest request) {
          String grantType = request.getParameter("grant_type");
          if (grantType != null && grantType.equals("password")) {
            UsernamePasswordAuthenticationToken result = new UsernamePasswordAuthenticationToken(
                request.getParameter("username"), request.getParameter("password"));
            result.setDetails(authenticationDetailsSource.buildDetails(request));
            return result;
          }
          if (grantType != null && grantType.equals("refresh_token")) {
            String refreshToken = request.getParameter("refresh_token");
            // TODO: handle the Refresh-Token
          }
          return null;
        }
      };
      tokenEndpointAuthenticationFilter.setAuthenticationDetailsSource(new WebAuthenticationDetailsSource());
      return tokenEndpointAuthenticationFilter;
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
      auth.ldapAuthentication()
          .ldapAuthoritiesPopulator(ldapAuthoritiesPopulator())
          .userDnPatterns(appendBaseDN("uid={0},ou=people"))
          .userDetailsContextMapper(new InetOrgPersonContextMapper())
          .authoritiesMapper(scopedInetOrgPersonContextMapper)
          .contextSource((LdapContextSource) contextSource);
    }

    private String appendBaseDN(String prefix) {
      if (StringUtils.isEmpty(prefix)) {
        return baseDN;
      }
      return prefix + ',' + baseDN;
    }

    @Bean
    public LdapAuthoritiesPopulator ldapAuthoritiesPopulator() {
      DefaultLdapAuthoritiesPopulator ldapAuthoritiesPopulator = new DefaultLdapAuthoritiesPopulator(contextSource, appendBaseDN("ou=groups"));
      ldapAuthoritiesPopulator.setConvertToUpperCase(false);
      ldapAuthoritiesPopulator.setRolePrefix("");
      return ldapAuthoritiesPopulator;
    }

    @Bean
    public UserDetailsService userDetailsService() {
      LdapUserSearch ldapUserSearch = new FilterBasedLdapUserSearch(appendBaseDN("ou=people"), "uid={0}", (LdapContextSource) contextSource);
      LdapUserDetailsService userDetailsService = new LdapUserDetailsService(ldapUserSearch, ldapAuthoritiesPopulator());
      userDetailsService.setUserDetailsMapper(scopedInetOrgPersonContextMapper);
      return userDetailsService;
    }

    @Override
    public void configure(WebSecurity web) throws Exception {
      web.debug(debug);
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
      http.antMatcher("/oauth/**")
          .authorizeRequests()
          .anyRequest().permitAll()
          .and()
          .securityContext()
          .and()
          .sessionManagement().sessionCreationPolicy(IF_REQUIRED)
          .sessionFixation().changeSessionId()
          .and()
          .exceptionHandling().authenticationEntryPoint(this::redirectToLoginPage)
          .and()
          .anonymous()
          .and()
          .headers()
          .and()
          .requestCache()
          .and()
          .servletApi()
          .and()
          .formLogin()
          .loginPage("/oauth/login")
          .permitAll()
          .successHandler(this::onAuthenticationSuccess)
          .failureHandler(this::redirectToLoginPageAfterError)
          .and()
          .csrf();
    }

    private void redirectToLoginPage(
        HttpServletRequest request,
        HttpServletResponse response,
        AuthenticationException authException)
        throws IOException, ServletException {
      UriComponentsBuilder uriComponentsBuilder =
          ServletUriComponentsBuilder.fromCurrentContextPath()
                                     .path("/oauth/login/redirect");

      addQueryParams(uriComponentsBuilder, request);
      response.sendRedirect(uriComponentsBuilder.toUriString());
    }

    private void addQueryParams(UriComponentsBuilder uriComponentsBuilder, HttpServletRequest request) {
      request.getParameterMap()
             .entrySet()
             .stream()
             .filter(entry -> Arrays.asList(RESPONSE_TYPE, CLIENT_ID, SCOPE, REDIRECT_URI, STATE)
                                    .contains(entry.getKey()))
             .filter(entry -> !Stream.of(entry.getValue())
                                     .allMatch(StringUtils::isEmpty))
             .forEach(entry -> uriComponentsBuilder.queryParam(entry.getKey(), (Object[]) entry.getValue()));
    }

    private void redirectToLoginPageAfterError(
        HttpServletRequest request,
        HttpServletResponse response,
        AuthenticationException authException)
        throws IOException, ServletException {
      UriComponentsBuilder uriComponentsBuilder =
          ServletUriComponentsBuilder.fromCurrentContextPath()
                                     .path("/oauth/login/redirect")
                                     .queryParam("error");
      addQueryParams(uriComponentsBuilder, request);
      response.sendRedirect(uriComponentsBuilder.toUriString());
    }

    private void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException {
      UriComponentsBuilder uriComponentsBuilder =
          ServletUriComponentsBuilder.fromCurrentContextPath()
                                     .path("/oauth/authorize");
      addQueryParams(uriComponentsBuilder, request);
      response.sendRedirect(uriComponentsBuilder.toUriString());
    }
  }

  @Configuration
  @EnableResourceServer
  @Order(2)
  public class ResourceServerConfiguration extends ResourceServerConfigurerAdapter {
    @Override
    public void configure(ResourceServerSecurityConfigurer resources) {
      resources.resourceId(AuthorizationServerConfiguration.INTERNAL_CLIENT_ID);
    }

    @Override
    public void configure(HttpSecurity http) throws Exception {
      http.authorizeRequests()
          .antMatchers("/api/**").authenticated()
          .anyRequest().permitAll();
    }
  }
}
