package comsang.mapper;


import comsang.bean.Make;
import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Param;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
@Mapper
public interface MakeMapper {

    /**
     * 查看医生时间
     *
     * @param doctorId
     * @return
     */
    List<Make> selectMake(@Param("doctorId") Integer doctorId);

}
