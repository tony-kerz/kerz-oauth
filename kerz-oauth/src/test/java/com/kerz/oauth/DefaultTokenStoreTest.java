package com.kerz.oauth;

import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;

/**
 * @author Dave Syer
 * 
 */
@RunWith(SpringJUnit4ClassRunner.class)
@ContextConfiguration
public class DefaultTokenStoreTest extends TestTokenStoreBase
{
	@Autowired
	private TokenStore tokenStore;

	@Override
	public TokenStore getTokenStore()
	{
		return tokenStore;
	}
}
