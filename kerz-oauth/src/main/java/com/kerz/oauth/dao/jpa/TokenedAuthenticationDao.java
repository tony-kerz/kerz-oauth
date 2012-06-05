package com.kerz.oauth.dao.jpa;

import java.util.List;

import org.springframework.data.jpa.repository.JpaRepository;

import com.kerz.oauth.domain.TokenedAuthentication;

public interface TokenedAuthenticationDao extends JpaRepository<TokenedAuthentication, Long>
{
	TokenedAuthentication findOneByTokenValue(String tokenValue);
	TokenedAuthentication findOneByAuthenticationKey(String authKey);
	List<TokenedAuthentication> findByUserName(String userName);
	List<TokenedAuthentication> findByClientId(String clientId);
}
