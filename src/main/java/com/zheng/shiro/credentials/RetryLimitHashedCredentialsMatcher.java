package com.zheng.shiro.credentials;

import java.util.concurrent.atomic.AtomicInteger;

import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.ExcessiveAttemptsException;
import org.apache.shiro.authc.credential.HashedCredentialsMatcher;
import org.apache.shiro.cache.Cache;
import org.apache.shiro.cache.CacheManager;

/**
 * 登录次数控制
 * 这里控制为最多输入5次
 * @author Administrator
 *
 */
public class RetryLimitHashedCredentialsMatcher extends HashedCredentialsMatcher {

	private Cache<String, AtomicInteger> passwordRetryCache;
	
	public RetryLimitHashedCredentialsMatcher(CacheManager cacheManager) {
        passwordRetryCache = cacheManager.getCache("passwordRetryCache");
    }
	
	@Override
	public boolean doCredentialsMatch(AuthenticationToken token, AuthenticationInfo info) {
		String username = (String) token.getPrincipal();
		
		AtomicInteger count = passwordRetryCache.get(username);
		if(count == null) {
			count = new AtomicInteger(0);
			passwordRetryCache.put(username, count);
		}
		
		if(count.incrementAndGet() > 5) {
			throw new ExcessiveAttemptsException();
		}
		
		boolean matches = super.doCredentialsMatch(token, info);
		if(matches) { //登录成功后就移除缓存中记录的登录次数
			passwordRetryCache.remove(username);
		}
		
		return matches;
	}
	
}
