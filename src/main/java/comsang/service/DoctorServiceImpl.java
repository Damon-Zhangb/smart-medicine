package comsang.service;

import comsang.bean.Doctor;
import comsang.mapper.DoctorMapper;
import org.springframework.stereotype.Service;

import javax.annotation.Resource;
import java.util.List;

@Service
public class DoctorServiceImpl implements DoctorService {
    @Resource
    DoctorMapper doctorMapper;

    @Override
    public Doctor doctorlogin(String doctozrNoba, String doctorPassword) {
        return doctorMapper.doctorlogin(doctozrNoba);
    }

    @Override
    public List<Doctor> selectDoctor(Integer id) {
        return doctorMapper.selectDoctor(id);
    }

    @Override
    public Doctor getDoctor(Integer id) {
        return doctorMapper.getDoctor(id);
    }

}
