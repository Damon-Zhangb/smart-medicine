package comsang.mapper;


import comsang.bean.Organization;
import org.apache.ibatis.annotations.Mapper;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
@Mapper
public interface OrganizationMapper {

    List<Organization> selectOrganization();

}
