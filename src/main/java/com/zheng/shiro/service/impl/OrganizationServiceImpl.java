package com.zheng.shiro.service.impl;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.zheng.shiro.dao.OrganizationDao;
import com.zheng.shiro.domain.Organization;
import com.zheng.shiro.service.OrganizationService;

@Service
public class OrganizationServiceImpl implements OrganizationService {

	@Autowired
	private OrganizationDao organizationDao;

	@Override
	public Organization createOrganization(Organization organization) {
		return organizationDao.createOrganization(organization);
	}

	@Override
	public Organization updateOrganization(Organization organization) {
		return organizationDao.updateOrganization(organization);
	}

	@Override
	public void deleteOrganization(Long organizationId) {
		organizationDao.deleteOrganization(organizationId);
	}

	@Override
	public Organization findOne(Long organizationId) {
		return organizationDao.findOne(organizationId);
	}

	@Override
	public List<Organization> findAll() {
		return organizationDao.findAll();
	}

	@Override
	public List<Organization> findAllWithExclude(Organization excludeOraganization) {
		return organizationDao.findAllWithExclude(excludeOraganization);
	}

	@Override
	public void move(Organization source, Organization target) {
		organizationDao.move(source, target);
	}

}
