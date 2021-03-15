package comsang.service;

import comsang.bean.Components;
import comsang.mapper.ComponentsMapper;
import org.springframework.stereotype.Service;

import javax.annotation.Resource;
import java.util.List;

@Service
public class ComponentsServiceImpl implements ComponentsService {

    @Resource
    ComponentsMapper componentsMapper;

    @Override
    public List<Components> selectComponents() {
        return componentsMapper.selectComponents();
    }
}
