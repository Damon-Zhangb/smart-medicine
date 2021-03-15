package comsang.mapper;

import comsang.bean.Information;
import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Param;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
@Mapper
public interface InformationMapper {

    /**
     * 注册
     *
     * @param information
     * @return
     */
    int insertInformation(Information information);

    /**
     * 患者登录
     *
     * @param phoneNumber
     * @return
     */
    Information loginInformation(@Param("phoneNumber") String phoneNumber);

    /**
     * 患者查询
     *
     * @param id
     * @return
     */
    Information selectById(Integer id);

    /**
     * 查看患者详情
     *
     * @param userId
     * @return
     */
    List<Information> selectDetails(@Param("userId") Integer userId);
}
