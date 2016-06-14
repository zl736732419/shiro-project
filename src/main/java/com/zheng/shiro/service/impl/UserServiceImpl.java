package com.zheng.shiro.service.impl;

import java.util.Collections;
import java.util.List;
import java.util.Set;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.zheng.shiro.dao.UserDao;
import com.zheng.shiro.domain.User;
import com.zheng.shiro.service.RoleService;
import com.zheng.shiro.service.UserService;
import com.zheng.shiro.utils.PasswordHelper;

@Service
public class UserServiceImpl implements UserService {

	@Autowired
	private UserDao userDao;
	@Autowired
	private PasswordHelper passwordHelper;
	@Autowired
	private RoleService roleService;

	@Override
	public User createUser(User user) {
		// 加密密码
		passwordHelper.encryptPassword(user);
		return userDao.createUser(user);
	}

	@Override
	public User updateUser(User user) {
		return userDao.updateUser(user);
	}

	@Override
	public void deleteUser(Long userId) {
		userDao.deleteUser(userId);
	}

	@Override
	public void changePassword(Long userId, String newPassword) {
		User user = userDao.findOne(userId);
		user.setPassword(newPassword);
		passwordHelper.encryptPassword(user);
		userDao.updateUser(user);
	}

	@Override
	public User findOne(Long userId) {
		return userDao.findOne(userId);
	}

	@Override
	public List<User> findAll() {
		return userDao.findAll();
	}

	@Override
	public User findByUsername(String username) {
		return userDao.findByUsername(username);
	}

	@SuppressWarnings("unchecked")
	@Override
	public Set<String> findRoles(String username) {
		User user = findByUsername(username);
		if (user == null) {
			return Collections.EMPTY_SET;
		}
		return roleService.findRoles(user.getRoleIds().toArray(new Long[0]));
	}

	@SuppressWarnings("unchecked")
	@Override
	public Set<String> findPermissions(String username) {
		User user =findByUsername(username);
        if(user == null) {
            return Collections.EMPTY_SET;
        }
        return roleService.findPermissions(user.getRoleIds().toArray(new Long[0]));
	}

}
