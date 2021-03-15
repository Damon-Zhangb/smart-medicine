package comsang.mapper;


import comsang.bean.Network;
import org.apache.ibatis.annotations.Mapper;
import org.springframework.stereotype.Repository;

@Repository
@Mapper
public interface NetworkMapper {

    Network selectNetwork();

}
