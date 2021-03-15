package comsang.service;

import comsang.bean.Components;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public interface ComponentsService {
    List<Components> selectComponents();
}
