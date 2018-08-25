package io.github.mufasa1976.spring.oauth2.authenticationserver.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;

@Configuration
@EnableWebSecurity(debug = true)
@Order
public class WebSecurityConfiguration extends WebSecurityConfigurerAdapter {
  @Bean
  public PasswordEncoder passwordEncoder() {
    return PasswordEncoderFactories.createDelegatingPasswordEncoder();
  }

  @Override
  protected void configure(AuthenticationManagerBuilder auth) throws Exception {
    PasswordEncoder passwordEncoder = passwordEncoder();
    auth.inMemoryAuthentication()
        .passwordEncoder(passwordEncoder)
        .withUser("user")
        .password(passwordEncoder.encode("password"))
        .roles("USER", "ADMIN");
    /*
    auth.ldapAuthentication()
        .rolePrefix("")
        .userDnPatterns("uid={0},ou=people")
        .userDetailsContextMapper(new InetOrgPersonContextMapper())
        .groupSearchBase("ou=groups")
        .groupSearchFilter("member={0}")
        .authoritiesMapper(authorities -> {
          List<GrantedAuthority> modifiedAuthorities = new ArrayList<>();
          authorities.stream()
                     .map(GrantedAuthority::getAuthority)
                     .map(authority -> new SimpleGrantedAuthority("ROLE_MODIFIED_" + authority))
                     .forEach(modifiedAuthorities::add);
          return modifiedAuthorities;
        })
        .contextSource()
        .ldif("classpath:schema.ldif");
        */
  }

  @Bean
  @Override
  public AuthenticationManager authenticationManagerBean() throws Exception {
    return super.authenticationManagerBean();
  }

  @Bean
  @Override
  public UserDetailsService userDetailsServiceBean() throws Exception {
    return super.userDetailsServiceBean();
  }
}
