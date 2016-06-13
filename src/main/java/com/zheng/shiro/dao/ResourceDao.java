package com.zheng.shiro.dao;

import java.util.List;

import com.zheng.shiro.domain.Resource;

public interface ResourceDao {
	public Resource createResource(Resource resource);

	public Resource updateResource(Resource resource);

	public void deleteResource(Long resourceId);

	Resource findOne(Long resourceId);

	List<Resource> findAll();
}
