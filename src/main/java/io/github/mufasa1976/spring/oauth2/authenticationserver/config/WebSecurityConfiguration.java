package io.github.mufasa1976.spring.oauth2.authenticationserver.config;

import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.ldap.core.ContextSource;
import org.springframework.ldap.core.support.LdapContextSource;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
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
import org.springframework.util.StringUtils;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;
import org.springframework.web.util.UriComponentsBuilder;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Arrays;
import java.util.stream.Stream;

import static org.springframework.security.config.http.SessionCreationPolicy.IF_REQUIRED;
import static org.springframework.security.oauth2.common.util.OAuth2Utils.*;

@Configuration
@EnableWebSecurity(debug = true)
@Order(Ordered.LOWEST_PRECEDENCE - 10)
@Slf4j
public class WebSecurityConfiguration extends WebSecurityConfigurerAdapter {
  private final ContextSource contextSource;

  private static final String ROLE_PREFIX = "";

  public WebSecurityConfiguration(ContextSource contextSource) {
    super(true);
    this.contextSource = contextSource;
  }

  @Bean
  @Override
  public AuthenticationManager authenticationManagerBean() throws Exception {
    return super.authenticationManagerBean();
  }

  @Bean
  public PasswordEncoder passwordEncoder() {
    return PasswordEncoderFactories.createDelegatingPasswordEncoder();
  }

  @Override
  protected void configure(AuthenticationManagerBuilder auth) throws Exception {
    auth.ldapAuthentication()
        .ldapAuthoritiesPopulator(ldapAuthoritiesPopulator())
        .userDnPatterns("uid={0},ou=people,dc=springframework,dc=org")
        .userDetailsContextMapper(new InetOrgPersonContextMapper())
        .authoritiesMapper(userDetailsContextMapper())
        .contextSource((LdapContextSource) contextSource);
  }

  @Bean
  public MyUserDetailsContextMapper userDetailsContextMapper() {
    return new MyUserDetailsContextMapper();
  }

  @Bean
  public LdapAuthoritiesPopulator ldapAuthoritiesPopulator() {
    DefaultLdapAuthoritiesPopulator ldapAuthoritiesPopulator = new DefaultLdapAuthoritiesPopulator(contextSource, "ou=groups,dc=springframework,dc=org");
    ldapAuthoritiesPopulator.setRolePrefix(ROLE_PREFIX);
    return ldapAuthoritiesPopulator;
  }

  @Bean
  public UserDetailsService userDetailsService() {
    LdapUserSearch ldapUserSearch = new FilterBasedLdapUserSearch("ou=people,dc=springframework,dc=org", "uid={0}", (LdapContextSource) contextSource);
    LdapUserDetailsService userDetailsService = new LdapUserDetailsService(ldapUserSearch, ldapAuthoritiesPopulator());
    userDetailsService.setUserDetailsMapper(userDetailsContextMapper());
    return userDetailsService;
  }

  @Override
  protected void configure(HttpSecurity http) throws Exception {
    http.requestMatchers()
        .antMatchers("/oauth/**", "/redirectToLogin", "/login")
        .and()
        .authorizeRequests().anyRequest().permitAll()
        .and()
        .securityContext()
        .and()
        .sessionManagement().sessionCreationPolicy(IF_REQUIRED)
        .sessionFixation().changeSessionId()
        .and()
        .anonymous()
        .and()
        .exceptionHandling().authenticationEntryPoint(this::redirectToLoginPage)
        .and()
        .headers()
        .and()
        .requestCache()
        .and()
        .servletApi()
        .and()
        .formLogin()
        .loginPage("/login")
        .successHandler(this::onAuthenticationSuccess)
        .permitAll()
        .and()
        .csrf()
        .and()
        .httpBasic();
  }

  private void redirectToLoginPage(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException) throws IOException, ServletException {
    UriComponentsBuilder uriComponentsBuilder =
        ServletUriComponentsBuilder.fromCurrentContextPath()
                                   .path("/redirectToLogin");

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

  private void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
    UriComponentsBuilder uriComponentsBuilder =
        ServletUriComponentsBuilder.fromCurrentContextPath()
                                   .path("/oauth/authorize");
    addQueryParams(uriComponentsBuilder, request);
    response.sendRedirect(uriComponentsBuilder.toUriString());
  }
}
