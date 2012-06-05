package com.kerz.oauth.domain;

import java.util.Date;

import javax.persistence.Entity;

import org.apache.commons.lang.builder.ToStringBuilder;
import org.springframework.data.jpa.domain.AbstractPersistable;

@Entity
public class TokenedAuthentication extends AbstractPersistable<Long>
{
	private static final long serialVersionUID = 1L;

	private String authenticationKey;
	private String clientAuthoritiesCsv;
	private String clientId;
	private Date expiration;
	private String refreshTokenValue;
	private String resourceIdsCsv;
	private String scopeCsv;
	private String tokenType;
	private String tokenValue;
	private String userAuthoritiesCsv;
	private String userName;

	public String getAuthenticationKey()
	{
		return authenticationKey;
	}

	public String getClientAuthoritiesCsv()
	{
		return clientAuthoritiesCsv;
	}

	public String getClientId()
	{
		return clientId;
	}

	public Date getExpiration()
	{
		return expiration;
	}

	public String getRefreshTokenValue()
	{
		return refreshTokenValue;
	}

	public String getResourceIdsCsv()
	{
		return resourceIdsCsv;
	}

	public String getScopeCsv()
	{
		return scopeCsv;
	}

	public String getTokenType()
	{
		return tokenType;
	}

	public String getTokenValue()
	{
		return tokenValue;
	}

	public String getUserAuthoritiesCsv()
	{
		return userAuthoritiesCsv;
	}

	public String getUserName()
	{
		return userName;
	}

	public void setAuthenticationKey(String authenticationKey)
	{
		this.authenticationKey = authenticationKey;
	}

	public void setClientAuthoritiesCsv(String authoritiesCsv)
	{
		this.clientAuthoritiesCsv = authoritiesCsv;
	}

	public void setClientId(String clientId)
	{
		this.clientId = clientId;
	}

	public void setExpiration(Date expiration)
	{
		this.expiration = expiration;
	}

	public void setRefreshTokenValue(String refreshTokenValue)
	{
		this.refreshTokenValue = refreshTokenValue;
	}

	public void setResourceIdsCsv(String resourceIdsCsv)
	{
		this.resourceIdsCsv = resourceIdsCsv;
	}

	public void setScopeCsv(String scopeCsv)
	{
		this.scopeCsv = scopeCsv;
	}

	public void setTokenType(String tokenType)
	{
		this.tokenType = tokenType;
	}

	public void setTokenValue(String tokenValue)
	{
		this.tokenValue = tokenValue;
	}

	public void setUserAuthoritiesCsv(String userAuthoritiesCsv)
	{
		this.userAuthoritiesCsv = userAuthoritiesCsv;
	}

	public void setUserName(String userId)
	{
		this.userName = userId;
	}

	@Override
	public String toString()
	{
		return ToStringBuilder.reflectionToString(this);
	}
}
