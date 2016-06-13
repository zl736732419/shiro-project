package com.zheng.shiro.bind;

import org.springframework.core.MethodParameter;
import org.springframework.web.bind.support.WebDataBinderFactory;
import org.springframework.web.context.request.NativeWebRequest;
import org.springframework.web.context.request.ServletWebRequest;
import org.springframework.web.method.support.HandlerMethodArgumentResolverComposite;
import org.springframework.web.method.support.ModelAndViewContainer;

/**
 * 处理@CurrentUser获取当前用户对象作为参数值
 * 
 * @author Administrator
 */
public class CurrentUserMethodArgumentRosovler extends HandlerMethodArgumentResolverComposite {

	public CurrentUserMethodArgumentRosovler() {
	}

	@Override
	public boolean supportsParameter(MethodParameter parameter) {
		if (parameter.hasParameterAnnotation(CurrentUser.class)) {
			return true;
		}

		return false;
	}

	@Override
	public Object resolveArgument(MethodParameter parameter, ModelAndViewContainer mavContainer,
			NativeWebRequest webRequest, WebDataBinderFactory binderFactory) throws Exception {
		CurrentUser currentUser = parameter.getParameterAnnotation(CurrentUser.class);
		if(currentUser == null) {
			return null;
		}
		String key = currentUser.value();
		ServletWebRequest request = (ServletWebRequest) webRequest;
		return request.getRequest().getSession().getAttribute(key);
	}

}
