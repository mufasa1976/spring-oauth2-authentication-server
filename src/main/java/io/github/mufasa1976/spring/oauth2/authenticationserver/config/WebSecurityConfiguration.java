package io.github.mufasa1976.spring.oauth2.authenticationserver.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.ldap.core.ContextSource;
import org.springframework.ldap.core.support.LdapContextSource;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.ldap.search.FilterBasedLdapUserSearch;
import org.springframework.security.ldap.search.LdapUserSearch;
import org.springframework.security.ldap.userdetails.DefaultLdapAuthoritiesPopulator;
import org.springframework.security.ldap.userdetails.InetOrgPersonContextMapper;
import org.springframework.security.ldap.userdetails.LdapAuthoritiesPopulator;
import org.springframework.security.ldap.userdetails.LdapUserDetailsService;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Configuration
@EnableWebSecurity(debug = true)
@Order(Ordered.LOWEST_PRECEDENCE - 10)
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
    http.antMatcher("/oauth/**")
        .authorizeRequests().anyRequest().permitAll()
        .and()
        .securityContext()
        .and()
        .sessionManagement()
        .and()
        .anonymous()
        .and()
        .exceptionHandling()
        .and()
        .headers()
        .and()
        .requestCache()
        .and()
        .servletApi()
        .and()
        .formLogin()
        .and()
        .csrf();
    super.configure(http);
  }

  private void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
    response.setStatus(HttpStatus.FOUND.value());
    response.setHeader(HttpHeaders.LOCATION, "oauth/authorize&response_type=code&client_id=my-server-frontend&scope=read%20write");
  }
}
