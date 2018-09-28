package io.github.mufasa1976.spring.oauth2.authenticationserver.config;

import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.web.filter.ForwardedHeaderFilter;
import org.springframework.web.servlet.config.annotation.ViewControllerRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

import javax.servlet.Filter;
import java.util.Collection;
import java.util.List;

@Configuration
@RequiredArgsConstructor
public class WebMvcConfiguration implements WebMvcConfigurer {
  private final Collection<HttpMessageConverter<?>> messageConverters;

  @Override
  public void addViewControllers(ViewControllerRegistry registry) {
    registry.addViewController("/**").setViewName("index");
  }

  @Override
  public void configureMessageConverters(List<HttpMessageConverter<?>> converters) {
    converters.addAll(messageConverters);
  }

  @Bean
  public Filter forwardedHeaderFilter() {
    return new ForwardedHeaderFilter();
  }
}
