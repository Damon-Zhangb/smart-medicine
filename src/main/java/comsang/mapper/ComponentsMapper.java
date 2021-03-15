package comsang.mapper;


import comsang.bean.Components;
import org.apache.ibatis.annotations.Mapper;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
@Mapper
public interface ComponentsMapper {

    List<Components> selectComponents();

}
