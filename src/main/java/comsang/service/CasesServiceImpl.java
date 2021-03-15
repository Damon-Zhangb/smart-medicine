package comsang.service;

import comsang.bean.Cases;
import comsang.bean.Generation;
import comsang.mapper.CasesMapper;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import javax.annotation.Resource;
import java.util.List;

@Service
@Transactional
public class CasesServiceImpl implements CasesService {

    @Resource
    CasesMapper casesMapper;

    @Resource
    GenerationService generationService;


    @Override
    @Transactional(rollbackFor = Exception.class)
    public int insertCases(final Cases cases, final String end) {
        if (this.casesMapper.insertCases(cases) > 0) {
            final Generation generation = new Generation();
            generation.setToId(cases.getCaseId());
            generation.setCipherText(end);
            System.out.println(end.length());
            return this.generationService.insert(generation);
        }
        return 0;
    }

    @Override
    public List<Cases> selectCases(final Integer information_id, final String starting_time, final String closing_time) {
        return this.casesMapper.selectCases(information_id, starting_time, closing_time);
    }

    @Override
    public List<Generation> selectByInId(final Integer information_id) {
        return this.casesMapper.selectByInId(information_id);
    }

    @Override
    public Cases selectByToId(final Integer id) {
        return this.casesMapper.selectByToId(id);
    }
}
