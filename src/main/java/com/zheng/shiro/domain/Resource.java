package com.zheng.shiro.domain;

import java.io.Serializable;

import org.apache.commons.lang3.builder.EqualsBuilder;
import org.apache.commons.lang3.builder.HashCodeBuilder;
import org.apache.commons.lang3.builder.ToStringBuilder;

public class Resource implements Serializable {
	private static final long serialVersionUID = 1L;

	private Long id;
	private String name; // 资源名称
	private ResourceType type = ResourceType.menu; // 资源类型
	private String url; // 资源路径
	private String permission; // 权限字符串
	private Long parentId; // 父编号
	private String parentIds; // 父编号列表
	private Boolean available = Boolean.FALSE;

	public static enum ResourceType {
		menu("菜单"), button("按钮");

		private final String info;

		private ResourceType(String info) {
			this.info = info;
		}

		public String getInfo() {
			return info;
		}
	}

	public Long getId() {
		return id;
	}

	public void setId(Long id) {
		this.id = id;
	}

	public String getName() {
		return name;
	}

	public void setName(String name) {
		this.name = name;
	}

	public ResourceType getType() {
		return type;
	}

	public void setType(ResourceType type) {
		this.type = type;
	}

	public String getUrl() {
		return url;
	}

	public void setUrl(String url) {
		this.url = url;
	}

	public String getPermission() {
		return permission;
	}

	public void setPermission(String permission) {
		this.permission = permission;
	}

	public Long getParentId() {
		return parentId;
	}

	public void setParentId(Long parentId) {
		this.parentId = parentId;
	}

	public String getParentIds() {
		return parentIds;
	}

	public void setParentIds(String parentIds) {
		this.parentIds = parentIds;
	}

	public Boolean getAvailable() {
		return available;
	}

	public void setAvailable(Boolean available) {
		this.available = available;
	}

	public boolean isRootNode() {
		return parentId == 0;
	}

	@Override
	public boolean equals(Object obj) {
		if (obj == this)
			return true;
		if (obj == null || !(obj instanceof Resource))
			return false;
		Resource other = (Resource) obj;
		return new EqualsBuilder().append(this.id, other.getId()).build();
	}

	@Override
	public int hashCode() {
		return new HashCodeBuilder().append(this.name).append(this.permission).append(this.url).append(this.available)
				.build();
	}

	@Override
	public String toString() {
		return new ToStringBuilder(this).append("name", this.name).append("permission", this.permission)
				.append("url", this.url).append("available", this.available).build();

	}

	public String makeSelfAsParentIds() {
		 return getParentIds() + getId() + "/";
	}

}
