package io.github.mufasa1976.spring.oauth2.authenticationserver.config;

import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpHeaders;
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
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.csrf.CsrfTokenRepository;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;
import org.springframework.web.util.UriComponentsBuilder;

import javax.servlet.RequestDispatcher;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletRequestWrapper;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Arrays;
import java.util.Base64;
import java.util.Optional;

import static org.springframework.security.config.http.SessionCreationPolicy.STATELESS;

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
        .antMatchers("/oauth/**", "/login")
        .and()
        .authorizeRequests().anyRequest().permitAll()
        .and()
        .securityContext()
        .and()
        .sessionManagement().sessionCreationPolicy(STATELESS)
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
        .csrf().csrfTokenRepository(getCsrfTokenRepository());
  }

  private void redirectToLoginPage(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException) throws IOException, ServletException {
    UriComponentsBuilder uriComponentsBuilder =
        ServletUriComponentsBuilder.fromCurrentContextPath()
                                   .path("/login");
    addQueryParams(uriComponentsBuilder, request);
    response.sendRedirect(uriComponentsBuilder.toUriString());
  }

  private void addQueryParams(UriComponentsBuilder uriComponentsBuilder, HttpServletRequest request) {
    request.getParameterMap()
           .entrySet()
           .stream()
           .filter(entry -> Arrays.asList("response_type", "client_id", "scope", "redirectUri")
                                  .contains(entry.getKey()))
           .forEach(entry -> uriComponentsBuilder.queryParam(entry.getKey(), entry.getValue()));
  }

  private void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
    UriComponentsBuilder uriComponentsBuilder = UriComponentsBuilder.fromPath("/oauth/authorize");
    addQueryParams(uriComponentsBuilder, request);
    RequestDispatcher requestDispatcher =
        Optional.of(request)
                .map(ServletRequest::getServletContext)
                .map(servletContext -> servletContext.getRequestDispatcher(uriComponentsBuilder.toUriString()))
                .orElseThrow(() -> new IllegalStateException("No RequestDispatcher available"));
    requestDispatcher.forward(new BasicAuthorizationHeaderHttpServletRequestWrapper(request), response);
  }

  private CsrfTokenRepository getCsrfTokenRepository() {
    CookieCsrfTokenRepository csrfTokenRepository = new CookieCsrfTokenRepository();
    csrfTokenRepository.setCookieHttpOnly(true);
    return csrfTokenRepository;
  }

  private static class BasicAuthorizationHeaderHttpServletRequestWrapper extends HttpServletRequestWrapper {
    public BasicAuthorizationHeaderHttpServletRequestWrapper(HttpServletRequest request) {
      super(request);
    }

    @Override
    public String getHeader(String name) {
      if (HttpHeaders.AUTHORIZATION.equals(name)) {
        String username = getParameter("username");
        String password = getParameter("password");
        return "Basic " + Base64.getEncoder().encodeToString((username + ':' + password).getBytes());
      }
      return super.getHeader(name);
    }
  }
}
