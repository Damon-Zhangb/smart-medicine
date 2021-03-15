package comsang.controller;

import comsang.service.ComponentsService;
import org.springframework.stereotype.Controller;

import javax.annotation.Resource;

@Controller
public class ComponentsController {

    @Resource
    ComponentsService componentsService;

/*
    @GetMapping("/api/bc/network")
    public MessageInfo selectNetwork(@RequestParam(required = true) String network_id){
    }
*/

}
