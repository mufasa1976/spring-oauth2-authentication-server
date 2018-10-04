package io.github.mufasa1976.spring.oauth2.authenticationserver.ldap.model;

import lombok.Data;
import org.springframework.ldap.odm.annotations.Attribute;
import org.springframework.ldap.odm.annotations.Entry;
import org.springframework.ldap.odm.annotations.Id;

import javax.naming.Name;

@Data
@Entry(base = "ou=groups", objectClasses = "groupOfNames")
public class Group {
  @Id
  private Name id;

  @Attribute(name = "cn")
  private String name;
}
