package comsang.mapper;


import comsang.bean.Doctor;
import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Param;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
@Mapper
public interface DoctorMapper {

    /**
     * 医生登录
     *
     * @param doctorNumber
     * @return
     */
    Doctor doctorlogin(@Param("doctorNumber") String doctorNumber);

    /**
     * 查看医生
     *
     * @param aotoId
     * @return
     */
    List<Doctor> selectDoctor(@Param("aotoId") Integer aotoId);

    /**
     * 通过id获取医生
     *
     * @param id
     * @return
     */
    Doctor getDoctor(Integer id);
}
