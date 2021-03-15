package comsang.mapper;

import comsang.bean.Cases;
import comsang.bean.Generation;
import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Param;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
@Mapper
public interface CasesMapper {

    /**
     * 添加病例
     *
     * @param cases
     * @return
     */
    int insertCases(Cases cases);

    /**
     * 查看病例本
     *
     * @param infoId
     * @param start
     * @param end
     * @return
     */
    List<Cases> selectCases(@Param("userId") Integer userId,
                            @Param("start") String start,
                            @Param("end") String end);

    List<Generation> selectByInId(Integer uid);

    /**
     * 根據toid查密文
     *
     * @param id
     * @return
     */
    Cases selectByToId(Integer id);
}
