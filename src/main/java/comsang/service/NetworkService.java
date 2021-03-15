package comsang.service;

import comsang.bean.Network;
import org.springframework.stereotype.Service;

@Service
public interface NetworkService {
    /**
     * 区块链管理
     *
     * @return
     */
    Network selectNetwork();

}
