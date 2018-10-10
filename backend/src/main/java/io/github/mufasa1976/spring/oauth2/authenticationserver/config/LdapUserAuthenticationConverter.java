package io.github.mufasa1976.spring.oauth2.authenticationserver.config;

import org.springframework.security.core.Authentication;
import org.springframework.security.ldap.userdetails.InetOrgPerson;
import org.springframework.security.ldap.userdetails.Person;
import org.springframework.security.oauth2.provider.token.DefaultUserAuthenticationConverter;

import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.function.Function;

public class LdapUserAuthenticationConverter extends DefaultUserAuthenticationConverter {
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
