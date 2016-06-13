package com.zheng.shiro.domain;

import java.io.Serializable;

import org.apache.commons.lang3.builder.EqualsBuilder;
import org.apache.commons.lang3.builder.HashCodeBuilder;
import org.apache.commons.lang3.builder.ToStringBuilder;

public class Organization implements Serializable {
	private static final long serialVersionUID = 1L;

	private Long id; // 编号
	private String name; // 组织机构名称
	private Long parentId; // 父编号
	private String parentIds; // 父编号列表，如1/2/
	private Boolean available = Boolean.FALSE;

	public Organization() {

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

	public String makeSelfAsParentIds() {
        return getParentIds() + getId() + "/";
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
		if (obj == null || !(obj instanceof Organization))
			return false;

		Organization other = (Organization) obj;
		return new EqualsBuilder().append(this.id, other.getId()).build();
	}

	@Override
	public int hashCode() {
		return new HashCodeBuilder().append(this.name).append(this.available).build();
	}

	@Override
	public String toString() {
		return new ToStringBuilder(this).append("name", this.name).append("available", this.available).build();
	}

}
