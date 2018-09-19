package io.github.mufasa1976.spring.oauth2.authenticationserver.model;

import lombok.Data;
import lombok.Getter;
import lombok.Setter;
import org.springframework.data.annotation.Id;
import org.springframework.data.redis.core.RedisHash;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;
import org.springframework.util.CollectionUtils;

import java.util.*;

import static lombok.AccessLevel.NONE;

@Data
@RedisHash("clientDetails")
public class RedisClientDetails implements ClientDetails {
  // Fields inherited by ClientDetails
  @Id
  private String clientId;
  private String clientSecret;
  @Getter(NONE)
  private Set<String> scopes = new HashSet<>();
  private Set<String> resourceIds = new HashSet<>();
  private Set<String> authorizedGrantTypes = new HashSet<>();
  @Getter(NONE)
  private Set<String> registeredRedirectUris;
  @Getter(NONE)
  private Set<String> autoApprovedScopes;
  private Collection<GrantedAuthority> authorities = new ArrayList<>();
  @Getter(NONE)
  private Map<String, Object> additionalInformations = new LinkedHashMap<>();
  private Integer accessTokenValiditySeconds;
  private Integer refreshTokenValiditySeconds;

  public static RedisClientDetails copyFrom(BaseClientDetails clientDetails) {
    RedisClientDetails clone = new RedisClientDetails();
    clone.setClientId(clientDetails.getClientId());
    clone.setClientSecret(clientDetails.getClientSecret());
    clone.setScopes(clientDetails.getScope());
    clone.setResourceIds(clientDetails.getResourceIds());
    clone.setAuthorizedGrantTypes(clientDetails.getAuthorizedGrantTypes());
    clone.setRegisteredRedirectUris(clientDetails.getRegisteredRedirectUri());
    clone.setAutoApprovedScopes(clientDetails.getAutoApproveScopes());
    clone.setAuthorities(clientDetails.getAuthorities());
    clone.setAdditionalInformations(clientDetails.getAdditionalInformation());
    clone.setAccessTokenValiditySeconds(clientDetails.getAccessTokenValiditySeconds());
    clone.setRefreshTokenValiditySeconds(clientDetails.getRefreshTokenValiditySeconds());
    return clone;
  }

  // non-standard Fields
  @Setter
  private String clientName;

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
