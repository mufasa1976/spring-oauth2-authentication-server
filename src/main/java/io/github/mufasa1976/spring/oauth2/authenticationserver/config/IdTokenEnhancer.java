package io.github.mufasa1976.spring.oauth2.authenticationserver.config;

import lombok.Getter;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.security.crypto.codec.Base64;
import org.springframework.security.jwt.Jwt;
import org.springframework.security.jwt.JwtHelper;
import org.springframework.security.jwt.crypto.sign.*;
import org.springframework.security.oauth2.common.DefaultOAuth2AccessToken;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.exceptions.InvalidTokenException;
import org.springframework.security.oauth2.common.util.JsonParser;
import org.springframework.security.oauth2.common.util.JsonParserFactory;
import org.springframework.security.oauth2.common.util.RandomValueStringGenerator;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.token.*;
import org.springframework.security.oauth2.provider.token.store.JwtClaimsSetVerifier;
import org.springframework.util.Assert;

import javax.validation.constraints.NotNull;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Stream;

@Slf4j
public class IdTokenEnhancer implements TokenEnhancer, InitializingBean {
  public static final String ID_TOKEN = "id_token";

  public static final String EXP = AccessTokenConverter.EXP;
  public static final String SUB = "sub";

  @Getter
  @Setter
  @NotNull
  private JwtClaimsSetVerifier jwtClaimsSetVerifier = new NoOpJwtClaimsSetVerifier();
  private JsonParser objectMapper = JsonParserFactory.create();
  @Setter
  private String verifierKey = new RandomValueStringGenerator().generate();
  @Setter
  private Signer signer = new MacSigner(verifierKey);
  private String signingKey = verifierKey;
  @Setter
  private SignatureVerifier verifier;

  @Getter
  @Setter
  @NotNull
  private UserAuthenticationConverter userAuthenticationConverter = new DefaultUserAuthenticationConverter();
  private AccessTokenConverter tokenConverter = new DefaultAccessTokenConverter();

  private String scopeAttribute = AccessTokenConverter.SCOPE;

  public Map<String, String> getKey() {
    Map<String, String> result = new LinkedHashMap<String, String>();
    result.put("alg", signer.algorithm());
    result.put("value", verifierKey);
    return result;
  }

  public void setKeyPair(KeyPair keyPair) {
    PrivateKey privateKey = keyPair.getPrivate();
    Assert.state(privateKey instanceof RSAPrivateKey, "KeyPair must be an RSA ");
    signer = new RsaSigner((RSAPrivateKey) privateKey);
    RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
    verifier = new RsaVerifier(publicKey);
    verifierKey = "-----BEGIN PUBLIC KEY-----\n" + new String(Base64.encode(publicKey.getEncoded()))
        + "\n-----END PUBLIC KEY-----";
  }

  public void setSigningKey(String key) {
    Assert.hasText(key);
    key = key.trim();

    this.signingKey = key;

    if (isPublic(key)) {
      signer = new RsaSigner(key);
      log.info("Configured with RSA signing key");
    } else {
      // Assume it's a MAC key
      this.verifierKey = key;
      signer = new MacSigner(key);
    }
  }

  private boolean isPublic(String key) {
    return key.startsWith("-----BEGIN");
  }

  public boolean isPublic() {
    return signer instanceof RsaSigner;
  }

  @Override
  public OAuth2AccessToken enhance(OAuth2AccessToken accessToken, OAuth2Authentication authentication) {
    Map<String, Object> decodedAccessToken = decode(accessToken.getValue());
    boolean openidAvailable = Optional.ofNullable(decodedAccessToken.get(scopeAttribute))
                                      .filter(Collection.class::isInstance)
                                      .map(Collection.class::cast)
                                      .map(Collection::stream)
                                      .orElseGet(Stream::empty)
                                      .filter(String.class::isInstance)
                                      .map(String.class::cast)
                                      .anyMatch("openid"::equals);
    if (!openidAvailable) {
      return accessToken;
    }

    DefaultOAuth2AccessToken enhancedAccessToken = new DefaultOAuth2AccessToken(accessToken);
    LinkedHashMap<String, Object> additionalInformation = new LinkedHashMap<>(accessToken.getAdditionalInformation());
    additionalInformation.put(ID_TOKEN, createIdToken(authentication, (Long) decodedAccessToken.get(AccessTokenConverter.EXP)));
    enhancedAccessToken.setAdditionalInformation(additionalInformation);

    return enhancedAccessToken;
  }

  protected Map<String, Object> decode(String token) {
    try {
      Jwt jwt = JwtHelper.decodeAndVerify(token, verifier);
      String claimsStr = jwt.getClaims();
      Map<String, Object> claims = objectMapper.parseMap(claimsStr);
      if (claims.containsKey(EXP) && claims.get(EXP) instanceof Integer) {
        Integer intValue = (Integer) claims.get(EXP);
        claims.put(AccessTokenConverter.EXP, new Long(intValue));
      }
      this.getJwtClaimsSetVerifier().verify(claims);
      return claims;
    } catch (Exception e) {
      throw new InvalidTokenException("Cannot convert access token to JSON", e);
    }
  }

  protected String createIdToken(OAuth2Authentication authentication, Long expiresInMsec) {
    Map<String, Object> tokenContent = new LinkedHashMap<>();
    tokenContent.put(EXP, expiresInMsec.toString());
    tokenContent.put(SUB, authentication.getName());
    try {
      String stringifiedMap = objectMapper.formatMap(tokenContent);
      return JwtHelper.encode(stringifiedMap, signer).getEncoded();
    } catch (Exception e) {
      throw new IllegalArgumentException("Cannot convert id token to JSON", e);
    }
  }

  @Override
  public void afterPropertiesSet() throws Exception {
    tokenConverter = new DefaultAccessTokenConverter();
    ((DefaultAccessTokenConverter) tokenConverter).setUserTokenConverter(userAuthenticationConverter);
    ((DefaultAccessTokenConverter) tokenConverter).setScopeAttribute(scopeAttribute);
    ((DefaultAccessTokenConverter) tokenConverter).setIncludeGrantType(false);

    if (verifier != null) {
      // Assume signer also set independently if needed
      return;
    }
    SignatureVerifier verifier = new MacSigner(verifierKey);
    try {
      verifier = new RsaVerifier(verifierKey);
    } catch (Exception e) {
      log.warn("Unable to create an RSA verifier from verifierKey (ignoreable if using MAC)");
    }
    // Check the signing and verification keys match
    if (signer instanceof RsaSigner) {
      byte[] test = "test".getBytes();
      try {
        verifier.verify(test, signer.sign(test));
        log.info("Signing and verification RSA keys match");
      } catch (InvalidSignatureException e) {
        log.error("Signing and verification RSA keys do not match");
      }
    } else if (verifier instanceof MacSigner) {
      // Avoid a race condition where setters are called in the wrong order. Use of
      // == is intentional.
      Assert.state(this.signingKey == this.verifierKey,
          "For MAC signing you do not need to specify the verifier key separately, and if you do it must match the signing key");
    }
    this.verifier = verifier;
  }

  private class NoOpJwtClaimsSetVerifier implements JwtClaimsSetVerifier {
    @Override
    public void verify(Map<String, Object> claims) throws InvalidTokenException {
    }
  }
}
