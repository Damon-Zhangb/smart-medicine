package comsang.service;


import comsang.bean.Make;
import comsang.mapper.MakeMapper;
import org.springframework.stereotype.Service;

import javax.annotation.Resource;
import java.util.List;

@Service
public class MakeServiceImpl implements MakeService {

    @Resource
    MakeMapper makeMapper;


    @Override
    public List<Make> selectMake(Integer doctorId) {
        return makeMapper.selectMake(doctorId);
    }
}
