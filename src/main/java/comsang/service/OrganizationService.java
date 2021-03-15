package comsang.service;

import comsang.bean.Organization;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public interface OrganizationService {

    /**
     * 区块链管理
     *
     * @return
     */
    List<Organization> selectOrganization();
}
