package comsang.controller;

import comsang.bean.MessageInfo;
import comsang.service.NetworkService;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.annotation.Resource;


@RestController
public class NetworkController {

    @Resource
    NetworkService networkService;

    @GetMapping("/api/bc/network")
    public MessageInfo select() {
        return new MessageInfo(200, networkService.selectNetwork());
    }
}
