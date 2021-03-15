package comsang.service;

import comsang.bean.Aoto;
import comsang.bean.Components;
import comsang.mapper.AotoMapper;
import comsang.mapper.ComponentsMapper;
import org.springframework.stereotype.Service;

import javax.annotation.Resource;
import java.util.List;

@Service
public class AotoServiceImpl implements AotoService {

    @Resource
    AotoMapper aotoMapper;


    @Override
    public List<Aoto> selectAoto() {
        return aotoMapper.selectAoto();
    }
}
