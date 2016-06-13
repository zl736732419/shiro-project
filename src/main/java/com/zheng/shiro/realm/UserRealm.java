package com.zheng.shiro.realm;

import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.LockedAccountException;
import org.apache.shiro.authc.SimpleAuthenticationInfo;
import org.apache.shiro.authc.UnknownAccountException;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.subject.PrincipalCollection;
import org.apache.shiro.util.ByteSource;
import org.springframework.beans.factory.annotation.Autowired;

import com.zheng.shiro.domain.User;
import com.zheng.shiro.service.UserService;

public class UserRealm extends AuthorizingRealm {

	@Autowired
	private UserService userService;

	@Override
	protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principals) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken token) throws AuthenticationException {
		String username = (String) token.getPrincipal();

		User user = userService.findByUsername(username);
		if (user == null) {
			throw new UnknownAccountException("当前用户不存在!");
		}

		if (user.getLocked() == Boolean.TRUE) {
			throw new LockedAccountException("当前用户已锁定!");
		}

		SimpleAuthenticationInfo info = new SimpleAuthenticationInfo(
				user.getUsername(), 
				user.getPassword(),
				ByteSource.Util.bytes(user.getCredentialsSalt()), 
				getName());
		return info;
	}

}
