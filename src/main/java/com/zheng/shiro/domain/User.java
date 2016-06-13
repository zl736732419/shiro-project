package com.zheng.shiro.domain;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;

import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.builder.EqualsBuilder;
import org.apache.commons.lang3.builder.HashCodeBuilder;
import org.apache.commons.lang3.builder.ToStringBuilder;
import org.springframework.util.CollectionUtils;

/**
 * 用户实体
 * 
 * @author Administrator
 *
 */
public class User implements Serializable {
	private static final long serialVersionUID = 1L;
	
	private Long id;
	private Long organizationId; // 所属公司
	private String username; // 用户名
	private String password; // 密码
	private String salt; // 加密密码的盐
	private List<Long> roleIds = new ArrayList<>(); // 拥有的角色列表
	private Boolean locked = Boolean.FALSE;

	public User() {

	}

	public User(String username, String password) {
		this.username = username;
		this.password = password;
	}

	public Long getId() {
		return id;
	}

	public void setId(Long id) {
		this.id = id;
	}

	public Long getOrganizationId() {
		return organizationId;
	}

	public void setOrganizationId(Long organizationId) {
		this.organizationId = organizationId;
	}

	public String getUsername() {
		return username;
	}

	public void setUsername(String username) {
		this.username = username;
	}

	public String getPassword() {
		return password;
	}

	public void setPassword(String password) {
		this.password = password;
	}

	public String getSalt() {
		return salt;
	}

	public void setSalt(String salt) {
		this.salt = salt;
	}

	public String getCredentialsSalt() {
		return username + salt;
	}

	public List<Long> getRoleIds() {
		return roleIds;
	}

	public String getRoleIdsStr() {
		if (CollectionUtils.isEmpty(roleIds)) {
			return "";
		}

		StringBuilder builder = new StringBuilder();
		for (Long roleId : roleIds) {
			builder.append(roleId).append(",");
		}

		return builder.toString().substring(0, builder.length() - 1);
	}

	public void setRoleIdsStr(String roleIdsStr) {
		if (StringUtils.isEmpty(roleIdsStr)) {
			return;
		}
		String[] roleIdStrs = roleIdsStr.split(",");
		for (String roleIdStr : roleIdStrs) {
			if (StringUtils.isEmpty(roleIdStr)) {
				continue;
			}
			getRoleIds().add(Long.valueOf(roleIdStr));
		}
	}

	public void setRoleIds(List<Long> roleIds) {
		this.roleIds = roleIds;
	}

	public Boolean getLocked() {
		return locked;
	}

	public void setLocked(Boolean locked) {
		this.locked = locked;
	}

	@Override
	public boolean equals(Object obj) {
		if (obj == this)
			return true;
		if (obj == null || !(obj instanceof User)) {
			return false;
		}

		User other = (User) obj;

		return new EqualsBuilder().append(this.id, other.getId()).build();
	}

	@Override
	public int hashCode() {
		return new HashCodeBuilder().append(this.id).append(this.username).append(this.password).append(this.salt)
				.append(this.locked).build();
	}

	@Override
	public String toString() {
		return new ToStringBuilder(this).append("username", username).append("password", password).append("salt", salt)
				.append("locked", locked).build();
	}

}
