package comsang.controller;

import comsang.bean.Components;
import comsang.bean.Health;
import comsang.bean.MessageInfo;
import comsang.service.ComponentsService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestTemplate;

import javax.annotation.Resource;
import java.util.List;

@RestController
public class HealthzController {

    @Resource
    RestTemplate restTemplate;
    @Resource
    ComponentsService componentsService;

    @GetMapping("/api/healthz")
    public MessageInfo healthz() {
        final List<Components> orgs = this.componentsService.selectComponents();
        for (final Components components : orgs) {
            final ResponseEntity<Health> responseEntity = this.restTemplate.getForEntity("http://127.0.0.1:8443/healthz", Health.class);
            components.setHealthCheck(responseEntity.getBody());
        }
        return new MessageInfo(200, orgs);
    }
}
