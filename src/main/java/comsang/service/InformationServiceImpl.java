package comsang.service;

import comsang.bean.Information;
import comsang.mapper.InformationMapper;
import org.springframework.stereotype.Service;

import javax.annotation.Resource;
import java.util.List;

@Service
public class InformationServiceImpl implements InformationService {

    @Resource
    InformationMapper informationMapper;

    @Override
    public int insertInformation(Information information) {

        return informationMapper.insertInformation(information);
    }

    @Override
    public Information loginInformation(String telephone) {
        return informationMapper.loginInformation(telephone);
    }

    @Override
    public List<Information> selectDetails(Integer userid) {
        return informationMapper.selectDetails(userid);
    }

    @Override
    public Information selectById(Integer id) {
        return informationMapper.selectById(id);
    }
}
