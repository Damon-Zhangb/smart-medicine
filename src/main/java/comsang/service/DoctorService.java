package comsang.service;

import comsang.bean.Doctor;
import org.apache.ibatis.annotations.Param;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public interface DoctorService {

    /**
     * 医生等入
     *
     * @param doctorNoba
     * @param doctorPassword
     * @return
     */
    Doctor doctorlogin(@Param("doctorNoba") String doctorNoba, @Param("doctorPassword") String doctorPassword);

    /**
     * 查看医生
     *
     * @param aotoId
     * @return
     */
    List<Doctor> selectDoctor(@Param("aotoId") Integer aotoId);

    Doctor getDoctor(Integer id);
}
