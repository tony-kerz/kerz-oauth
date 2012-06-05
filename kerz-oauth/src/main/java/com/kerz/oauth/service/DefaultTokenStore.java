package com.kerz.oauth.service;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.oauth2.common.ExpiringOAuth2RefreshToken;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.OAuth2RefreshToken;
import org.springframework.security.oauth2.common.util.OAuth2Utils;
import org.springframework.security.oauth2.provider.AuthorizationRequest;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.token.AuthenticationKeyGenerator;
import org.springframework.security.oauth2.provider.token.DefaultAuthenticationKeyGenerator;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.util.StringUtils;

import com.kerz.oauth.dao.jpa.TokenedAuthenticationDao;
import com.kerz.oauth.domain.TokenedAuthentication;

public class DefaultTokenStore implements TokenStore
{
  private AuthenticationKeyGenerator authenticationKeyGenerator = new DefaultAuthenticationKeyGenerator();
  private Logger log = LoggerFactory.getLogger(DefaultTokenStore.class);
  private TokenedAuthenticationDao tokenedAuthenticationDao;

  private Collection<OAuth2AccessToken> convert(List<TokenedAuthentication> tokAuths)
  {
    Collection<OAuth2AccessToken> result = new ArrayList<OAuth2AccessToken>(tokAuths.size());
    for (TokenedAuthentication tokAuth : tokAuths)
    {
      result.add(convert(tokAuth));
    }
    return result;
  }

  private OAuth2AccessToken convert(TokenedAuthentication tokAuth)
  {
    OAuth2AccessToken accessToken = null;
    if (tokAuth != null)
    {
      Map<String, String> tokenParams = new HashMap<String, String>();

      tokenParams.put(OAuth2AccessToken.ACCESS_TOKEN, tokAuth.getTokenValue());

      Date expiration = tokAuth.getExpiration();
      if (expiration != null)
      {
        long expiresInMillis = expiration.getTime() - System.currentTimeMillis();
        long expiresInSeconds = expiresInMillis / 1000;
        tokenParams.put(OAuth2AccessToken.EXPIRES_IN, Long.toString(expiresInSeconds));
      }
      String refreshTokenValue = tokAuth.getRefreshTokenValue();
      if (refreshTokenValue != null)
      {
        tokenParams.put(OAuth2AccessToken.REFRESH_TOKEN, refreshTokenValue);
      }

      String scopeCsv = tokAuth.getScopeCsv();
      if (scopeCsv != null)
      {
        tokenParams.put(OAuth2AccessToken.SCOPE, scopeCsv);
      }

      String tokenType = tokAuth.getTokenType();
      if (tokenType != null)
      {
        tokenParams.put(OAuth2AccessToken.TOKEN_TYPE, tokenType);
      }

      accessToken = OAuth2AccessToken.valueOf(tokenParams);
    }

    return accessToken;
  }

//  @Override
//  public Collection<OAuth2AccessToken> findTokensByClientId(String clientId)
//  {
//    return convert(tokenedAuthenticationDao.findByClientId(clientId));
//  }

//  @Override
//  public Collection<OAuth2AccessToken> findTokensByUserName(String userName)
//  {
//    return convert(tokenedAuthenticationDao.findByUserName(userName));
//  }

  @Override
  public OAuth2AccessToken getAccessToken(OAuth2Authentication authentication)
  {
    log.debug("oa2-auth={}", authentication);
    String authKey = authenticationKeyGenerator.extractKey(authentication);
    // select token_id, token from oauth_access_token where authentication_id = ?
    TokenedAuthentication tokAuth = tokenedAuthenticationDao.findOneByAuthenticationKey(authKey);
    log.debug("obtained tokened-auth={} for key={}", tokAuth, authKey);
    return convert(tokAuth);
  }

  private Collection<GrantedAuthority> getAuthorities(String authoritiesCsv)
  {
    Collection<GrantedAuthority> authorities = null;
    if (StringUtils.hasText(authoritiesCsv))
    {
      authorities = new ArrayList<GrantedAuthority>();
      Set<String> authoritySet = OAuth2Utils.parseParameterList(authoritiesCsv);
      for (String authority : authoritySet)
      {
        authorities.add(new SimpleGrantedAuthority(authority));
      }
    }
    return authorities;
  }

  private String getAuthoritiesCsv(Collection<? extends GrantedAuthority> grantedAuthorities)
  {
    String result = null;
    if ((grantedAuthorities != null) && (grantedAuthorities.size() > 0))
    {
      Set<String> authorities = new HashSet<String>();
      for (GrantedAuthority grantedAuthority : grantedAuthorities)
      {
        authorities.add(grantedAuthority.getAuthority());
      }
      result = OAuth2Utils.formatParameterList(authorities);
    }
    return result;
  }

  @Override
  public OAuth2AccessToken readAccessToken(String tokenValue)
  {
    log.debug("token-value={}", tokenValue);
    // select token_id, token from oauth_access_token where token_id = ?
    TokenedAuthentication tokAuth = tokenedAuthenticationDao.findOneByTokenValue(tokenValue);
    log.debug("obtained tokened-auth={} for token-value={}", tokAuth, tokenValue);
    return convert(tokAuth);
  }

  @Override
  //public OAuth2Authentication readAuthenticationForRefreshToken(String tokenValue)
  public OAuth2Authentication readAuthentication(ExpiringOAuth2RefreshToken token)
  {
    // select token_id, authentication from oauth_refresh_token where token_id = ?
    throw new RuntimeException("not supported");
  }

  @Override
  //public OAuth2Authentication readAuthentication(String tokenValue)
  public OAuth2Authentication readAuthentication(OAuth2AccessToken oa2AccessToken)
  {
    String tokenValue = oa2AccessToken.getValue();
    log.debug("token-value={}", tokenValue);
    // select token_id, authentication from oauth_access_token where token_id = ?
    TokenedAuthentication tokAuth = tokenedAuthenticationDao.findOneByTokenValue(tokenValue);
    log.debug("obtained tokened-auth={} for token-value={}", tokAuth, tokenValue);

    OAuth2Authentication oa2Auth = null;
    if (tokAuth != null)
    {
      Collection<GrantedAuthority> clientAuthorities = getAuthorities(tokAuth.getClientAuthoritiesCsv());
      Collection<GrantedAuthority> userAuthorities = getAuthorities(tokAuth.getUserAuthoritiesCsv());

      Collection<String> resourceIds = null;
      String resourceIdsCsv = tokAuth.getResourceIdsCsv();
      if (StringUtils.hasText(resourceIdsCsv))
      {
        resourceIds = OAuth2Utils.parseParameterList(resourceIdsCsv);
      }

      Set<String> scope = null;
      String scopeCsv = tokAuth.getScopeCsv();
      if (StringUtils.hasText(scopeCsv))
      {
        scope = OAuth2Utils.parseParameterList(scopeCsv);
      }

      AuthorizationRequest clientAuthentication = new AuthorizationRequest(tokAuth.getClientId(), scope, clientAuthorities,
          resourceIds);

      User user = new User(tokAuth.getUserName(), "dummy-password", userAuthorities);
      UsernamePasswordAuthenticationToken userAuthentication = new UsernamePasswordAuthenticationToken(user, null, userAuthorities);

      oa2Auth = new OAuth2Authentication(clientAuthentication, userAuthentication);
    }

    return oa2Auth;
  }

  @Override
  public ExpiringOAuth2RefreshToken readRefreshToken(String tokenValue)
  {
    throw new RuntimeException("not supported");
  }

  @Override
  public void removeAccessToken(String tokenValue)
  {
    log.debug("token-value={}", tokenValue);
    // throw new RuntimeException("not supported");
    TokenedAuthentication tokAuth = tokenedAuthenticationDao.findOneByTokenValue(tokenValue);
    if (tokAuth != null)
    {
      tokenedAuthenticationDao.delete(tokAuth);
    }
  }

  @Override
  public void removeAccessTokenUsingRefreshToken(String refreshToken)
  {
    throw new RuntimeException("not supported");
  }

  @Override
  public void removeRefreshToken(String tokenValue)
  {
    throw new RuntimeException("not supported");
  }

  public void setTokenedAuthenticationDao(TokenedAuthenticationDao tokenedAuthenticationDao)
  {
    this.tokenedAuthenticationDao = tokenedAuthenticationDao;
  }

  @Override
  public void storeAccessToken(OAuth2AccessToken token, OAuth2Authentication authentication)
  {
    log.debug("oa2-access-token={}, oa2-auth={}", token, authentication);
    // insert into oauth_access_token (token_id, token, authentication_id, authentication, refresh_token) values (?, ?, ?, ?, ?)
    // new Object[] { token.getValue(), new SqlLobValue(SerializationUtils.serialize(token)),
    // authenticationKeyGenerator.extractKey(authentication), new SqlLobValue(SerializationUtils.serialize(authentication)),
    // refreshToken }
    // new int[] { Types.VARCHAR, Types.BLOB, Types.VARCHAR, Types.BLOB, Types.VARCHAR }

    Authentication userAuth = authentication.getUserAuthentication();
    AuthorizationRequest authRequest = authentication.getAuthorizationRequest();

    TokenedAuthentication tokAuth = new TokenedAuthentication();
    tokAuth.setAuthenticationKey(authenticationKeyGenerator.extractKey(authentication));
    tokAuth.setClientId(authRequest.getClientId());
    tokAuth.setExpiration(token.getExpiration());
    OAuth2RefreshToken refreshToken = token.getRefreshToken();
    if (refreshToken != null)
    {
      tokAuth.setRefreshTokenValue(refreshToken.getValue());
    }

    tokAuth.setScopeCsv(OAuth2Utils.formatParameterList(token.getScope()));

    tokAuth.setClientAuthoritiesCsv(getAuthoritiesCsv(authRequest.getAuthorities()));

    tokAuth.setUserAuthoritiesCsv(getAuthoritiesCsv(userAuth.getAuthorities()));

    tokAuth.setResourceIdsCsv(OAuth2Utils.formatParameterList(authRequest.getResourceIds()));

    tokAuth.setTokenType(token.getTokenType());
    tokAuth.setTokenValue(token.getValue());
    tokAuth.setUserName(userAuth.getName());
    tokenedAuthenticationDao.save(tokAuth);
  }

  @Override
  public void storeRefreshToken(ExpiringOAuth2RefreshToken refreshToken, OAuth2Authentication authentication)
  {
    throw new RuntimeException("not supported");
  }
}
