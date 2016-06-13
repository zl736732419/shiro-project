package com.zheng.shiro.filter;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;

import org.apache.shiro.SecurityUtils;
import org.apache.shiro.web.filter.PathMatchingFilter;
import org.springframework.beans.factory.annotation.Autowired;

import com.zheng.shiro.service.UserService;
import com.zheng.shiro.utils.Constants;

/**
 * 获取当前用户信息，并保存到session中
 * 
 * @author Administrator
 *
 */
public class SysUserFilter extends PathMatchingFilter {
	@Autowired
	private UserService userService;

	@Override
	protected boolean preHandle(ServletRequest request, ServletResponse response) throws Exception {
		String username = (String) SecurityUtils.getSubject().getPrincipal();
		HttpServletRequest req = (HttpServletRequest) request;
		HttpSession session = req.getSession();
		if(session.getAttribute(Constants.CURRENT_USER) == null) {
			session.setAttribute(Constants.CURRENT_USER, userService.findByUsername(username));
		}

		return true;
	}
}
