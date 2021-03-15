package comsang.controller;

import comsang.bean.MessageInfo;
import comsang.service.AotoService;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.annotation.Resource;

@RestController
public class AotoController {

    @Resource
    AotoService aotoService;

    @GetMapping("/api/select/aoto")
    public MessageInfo select() {
        return new MessageInfo(200, aotoService.selectAoto());
    }


}
