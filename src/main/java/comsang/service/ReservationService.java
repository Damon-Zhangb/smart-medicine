package comsang.service;

import comsang.bean.Reservation;
import org.apache.ibatis.annotations.Param;
import org.springframework.stereotype.Service;

import java.util.List;


@Service
public interface ReservationService {

    /**
     * 预约单
     *
     * @param reservation
     * @return
     */
    int insertReservation(Reservation reservation);

    /**
     * 医生查看预约单
     *
     * @param doctorId
     * @param dq
     * @param count
     * @return
     */
    List<Reservation> selectReserv(@Param("doctorId") Integer doctorId, @Param("dq") Integer dq, @Param("count") Integer count);

    /**
     * 患者查看预约单
     *
     * @param patientId
     * @param dq
     * @param count
     * @return
     */
    List<Reservation> selectResInoform(@Param("patientId") Integer patientId, @Param("dq") Integer dq, @Param("count") Integer count);

    /**
     * 分页
     *
     * @param doctorId
     * @return
     */
    int num(@Param("doctorId") Integer doctorId);

    /**
     * 修改孙权码状态
     *
     * @param reservation
     * @return
     */
    int updateCodesate(Reservation reservation);

    /**
     * 修改预约状态
     *
     * @param reservation
     * @return
     */
    int updatesate(Reservation reservation);
}
