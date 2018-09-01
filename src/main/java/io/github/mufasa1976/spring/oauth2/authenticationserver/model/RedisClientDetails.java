package io.github.mufasa1976.spring.oauth2.authenticationserver.model;

import lombok.*;
import org.springframework.data.annotation.Id;
import org.springframework.data.redis.core.RedisHash;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.util.CollectionUtils;

import java.util.Collection;
import java.util.Map;
import java.util.Set;

import static lombok.AccessLevel.NONE;
import static lombok.AccessLevel.PRIVATE;

@Data
@Setter(NONE)
@NoArgsConstructor
@AllArgsConstructor(access = PRIVATE)
@Builder
@RedisHash("clientDetails")
public class RedisClientDetails implements ClientDetails {
  @Id
  private String clientId;
  private String clientSecret;
  @Singular
  @Getter(NONE)
  private Set<String> scopes;
  @Singular
  private Set<String> resourceIds;
  @Singular
  private Set<String> authorizedGrantTypes;
  @Singular("registeredRedirectUri")
  @Getter(NONE)
  private Set<String> registeredRedirectUris;
  @Singular
  @Getter(NONE)
  private Set<String> autoApprovedScopes;
  @Singular
  private Collection<GrantedAuthority> authorities;
  @Singular
  @Getter(NONE)
  private Map<String, Object> additionalInformations;
  private Integer accessTokenValiditySeconds;
  private Integer refreshTokenValiditySeconds;

  @Override
  public boolean isSecretRequired() {
    return clientSecret != null;
  }

  @Override
  public Set<String> getScope() {
    return scopes;
  }

  @Override
  public boolean isScoped() {
    return !CollectionUtils.isEmpty(scopes);
  }

  @Override
  public Set<String> getRegisteredRedirectUri() {
    return registeredRedirectUris;
  }

  @Override
  public boolean isAutoApprove(String scope) {
    if (autoApprovedScopes == null) {
      return false;
    }
    for (String auto : autoApprovedScopes) {
      if (auto.equals("true") || scope.matches(auto)) {
        return true;
      }
    }
    return false;
  }

  @Override
  public Map<String, Object> getAdditionalInformation() {
    return additionalInformations;
  }
}
