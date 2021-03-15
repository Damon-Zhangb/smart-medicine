package comsang.controller;

import comsang.bean.MessageInfo;
import comsang.service.MakeService;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import javax.annotation.Resource;

@RestController
public class MakeController {
    @Resource
    MakeService makeService;


    @GetMapping("/api/department")
    public MessageInfo selectMake(@RequestParam("doctorId") Integer doctorId) {
        return new MessageInfo(200, makeService.selectMake(doctorId));
    }
}
