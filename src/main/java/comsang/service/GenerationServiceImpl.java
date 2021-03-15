package comsang.service;

import comsang.bean.Cases;
import comsang.bean.Generation;
import comsang.bean.Reservation;
import comsang.mapper.GenerationMapper;
import org.springframework.stereotype.Service;

import javax.annotation.Resource;

@Service
public class GenerationServiceImpl implements GenerationService {

    @Resource
    GenerationMapper generationMapper;

    @Override
    public int insert(Generation generation) {
        return generationMapper.insert(generation);
    }


}
