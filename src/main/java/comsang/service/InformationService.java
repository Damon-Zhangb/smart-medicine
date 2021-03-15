package comsang.service;

import comsang.bean.Information;
import org.apache.ibatis.annotations.Param;
import org.springframework.stereotype.Service;

import java.util.List;


@Service
public interface InformationService {

    /**
     * 注册
     *
     * @param information
     * @return
     */
    int insertInformation(Information information);

    /**
     * 患者等入
     *
     * @param telephone
     * @return
     */
    Information loginInformation(@Param("telephone") String telephone);

    /**
     * 查看患者详情
     *
     * @param userid
     * @return
     */
    List<Information> selectDetails(@Param("userid") Integer userid);

    /**
     * 患者查询
     *
     * @param id
     * @return
     */
    Information selectById(Integer id);
}
