package comsang.mapper;

import comsang.bean.Generation;
import org.apache.ibatis.annotations.Mapper;
import org.springframework.stereotype.Repository;

@Repository
@Mapper
public interface GenerationMapper {

    /**
     * 添加密文
     *
     * @param generation
     * @return
     */
    int insert(Generation generation);

}
