package io.github.mufasa1976.spring.oauth2.authenticationserver;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.core.io.Resource;

import javax.validation.constraints.NotNull;
import java.util.ArrayList;
import java.util.List;

@Data
@ConfigurationProperties("oauth2-server")
public class ApplicationProperties {
  @NotNull
  private Resource keystore;

  @NotNull
  private String clientName = "OAuth2 Server";

  private List<String> allowedLdapGroupsForServerAdministration = new ArrayList<>();

  @NotNull
  private String ldapGroupFilter = "(objectClass=groupOfNames)";

  private boolean checkUserScope = false;
}
