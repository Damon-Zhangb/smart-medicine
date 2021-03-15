package comsang.service;

import comsang.bean.Components;
import comsang.bean.Network;
import comsang.mapper.NetworkMapper;
import org.springframework.stereotype.Service;

import javax.annotation.Resource;


@Service
public class NetworkServiceImpl implements NetworkService {

    @Resource
    NetworkMapper networkMapper;

    @Override
    public Network selectNetwork() {
        return networkMapper.selectNetwork();
    }

}
