package comsang.service;

import comsang.bean.Components;
import comsang.bean.Network;
import comsang.bean.Organization;
import comsang.mapper.NetworkMapper;
import comsang.mapper.OrganizationMapper;
import org.springframework.stereotype.Service;

import javax.annotation.Resource;
import java.util.List;


@Service
public class OrganizationServiceImpl implements OrganizationService {

    @Resource
    OrganizationMapper organizationMapper;


    @Override
    public List<Organization> selectOrganization() {
        return organizationMapper.selectOrganization();
    }
}
