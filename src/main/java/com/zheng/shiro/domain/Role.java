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
 * 角色实体
 * 
 * @author Administrator
 *
 */
public class Role implements Serializable {
	private static final long serialVersionUID = 1L;
	
	private Long id; // 编号
	private String role; // 角色标识 程序中判断使用,如"admin"
	private String description; // 角色描述,UI界面显示使用
	private List<Long> resourceIds = new ArrayList<>(); // 拥有的资源
	private Boolean available = Boolean.FALSE; // 是否可用,如果不可用将不会添加给用户

	public Role() {

	}

	public Role(String role, String description, Boolean available) {
		this.role = role;
		this.description = description;
		this.available = available;
	}

	public Long getId() {
		return id;
	}

	public void setId(Long id) {
		this.id = id;
	}

	public String getRole() {
		return role;
	}

	public void setRole(String role) {
		this.role = role;
	}

	public String getDescription() {
		return description;
	}

	public void setDescription(String description) {
		this.description = description;
	}

	public List<Long> getResourceIds() {
		return resourceIds;
	}

	public String getResourceIdsStr() {
		if (CollectionUtils.isEmpty(resourceIds)) {
			return "";
		}
		StringBuilder s = new StringBuilder();
		for (Long resourceId : resourceIds) {
			s.append(resourceId);
			s.append(",");
		}
		return s.toString().substring(0, s.length() - 1);
	}

	public void setResourceIdsStr(String resourceIdsStr) {
		if (StringUtils.isEmpty(resourceIdsStr)) {
			return;
		}
		String[] resourceIdStrs = resourceIdsStr.split(",");
		for (String resourceIdStr : resourceIdStrs) {
			if (StringUtils.isEmpty(resourceIdStr)) {
				continue;
			}
			getResourceIds().add(Long.valueOf(resourceIdStr));
		}
	}

	public void setResourceIds(List<Long> resourceIds) {
		this.resourceIds = resourceIds;
	}

	public Boolean getAvailable() {
		return available;
	}

	public void setAvailable(Boolean available) {
		this.available = available;
	}

	@Override
	public boolean equals(Object obj) {
		if (obj == this)
			return true;
		if (obj == null || !(obj instanceof Role))
			return false;

		Role other = (Role) obj;
		return new EqualsBuilder().append(this.id, other.getId()).build();
	}

	@Override
	public int hashCode() {
		return new HashCodeBuilder().append(this.role).append(this.description).append(this.available).build();
	}

	@Override
	public String toString() {
		return new ToStringBuilder(this).append("role", this.role).append("description", this.description)
				.append("available", this.available).build();
	}

}
