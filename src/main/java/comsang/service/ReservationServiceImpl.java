package comsang.service;

import comsang.bean.Reservation;
import comsang.mapper.ReservationMapper;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import javax.annotation.Resource;
import java.util.List;

@Service
@Transactional
public class ReservationServiceImpl implements ReservationService {

    @Resource
    ReservationMapper reservationMapper;


    @Resource
    GenerationService generationService;


    @Override
    public int insertReservation(Reservation reservation) {
        return reservationMapper.insertReservation(reservation);
    }

    @Override
    public List<Reservation> selectReserv(Integer doctor_id, Integer dq, Integer count) {
        dq = count * (dq - 1);
        return reservationMapper.selectReserv(doctor_id, dq, count);
    }

    @Override
    public List<Reservation> selectResInoform(Integer patient_id, Integer dq, Integer count) {
        dq = count * (dq - 1);
        return reservationMapper.selectResInoform(patient_id, dq, count);
    }

    @Override
    public int num(Integer doctor_id) {
        return reservationMapper.num(doctor_id);
    }

    @Override
    public int updateCodesate(Reservation reservation) {
        return reservationMapper.updateCodesate(reservation);
    }

    @Override
    public int updatesate(Reservation reservation) {
        return reservationMapper.updatesate(reservation);
    }


}
