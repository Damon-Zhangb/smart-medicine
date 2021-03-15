package comsang.service;

import comsang.bean.Cases;
import comsang.bean.Generation;
import org.apache.ibatis.annotations.Param;
import org.springframework.stereotype.Service;

import java.util.List;


@Service
public interface CasesService {

    /**
     * 添加病例
     *
     * @param cases
     * @param end
     * @return
     */
    int insertCases(Cases cases, String end);

    /**
     * 查看病例本
     *
     * @param information_id
     * @param starting_time
     * @param closing_time
     * @return
     */
    List<Cases> selectCases(@Param("information_id") Integer information_id,
                            @Param("starting_time") String starting_time,
                            @Param("closing_time") String closing_time);

    /**
     * 查看加密病例
     *
     * @param information_id
     * @return
     */
    List<Generation> selectByInId(Integer information_id);

    /**
     * 根據toid查密文
     *
     * @param id
     * @return
     */
    Cases selectByToId(Integer id);
}
