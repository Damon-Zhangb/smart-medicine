package comsang.service;

import comsang.bean.Make;
import org.apache.ibatis.annotations.Param;
import org.springframework.stereotype.Service;

import java.util.List;


@Service
public interface MakeService {
    /**
     * 查看医生时间
     *
     * @param doctorId
     * @return
     */
    List<Make> selectMake(@Param("doctorId") Integer doctorId);
}
