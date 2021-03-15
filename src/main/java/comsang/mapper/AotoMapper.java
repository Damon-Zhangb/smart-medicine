package comsang.mapper;


import comsang.bean.Aoto;
import org.apache.ibatis.annotations.Mapper;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
@Mapper
public interface AotoMapper {

    List<Aoto> selectAoto();

}
