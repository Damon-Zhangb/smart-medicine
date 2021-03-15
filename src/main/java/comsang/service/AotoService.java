package comsang.service;

import comsang.bean.Aoto;
import org.springframework.stereotype.Service;

import java.util.List;


@Service
public interface AotoService {

    List<Aoto> selectAoto();

}
