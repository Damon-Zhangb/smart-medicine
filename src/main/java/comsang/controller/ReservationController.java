package comsang.controller;


import comsang.bean.Doctor;
import comsang.bean.Information;
import comsang.bean.MessageInfo;
import comsang.bean.Reservation;
import comsang.service.DoctorService;
import comsang.service.ReservationService;
import org.springframework.web.bind.annotation.*;

import javax.annotation.Resource;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

@RestController
public class ReservationController {

    @Resource
    ReservationService reservationService;

    @Resource
    DoctorService doctorService;


    @PostMapping("/api/reservation")
    public MessageInfo insert(@RequestBody Reservation reservation, final HttpServletRequest request) {
        //16位key （密钥）
        reservation.setAuthorizationCode(UUID.randomUUID().toString().substring(0, 4));
        try {
            if (this.reservationService.insertReservation(reservation) == 0) {
                return new MessageInfo(200, "失败");
            }
        } catch (final Exception e) {
            return new MessageInfo(200, "异常:" + e.getMessage());
        }
        return new MessageInfo(200, "成功");
    }

    @GetMapping("/api/reservation/doctor")
    public Map<String, Object> selectDoct(final HttpSession session, final HttpServletRequest request,
                                          @RequestParam(defaultValue = "1") final Integer page,
                                          @RequestParam(defaultValue = "2") final Integer size) {
        final Map<String, Object> map = new HashMap<String, Object>();
        //拿到session
        final Doctor doctor = (Doctor) session.getAttribute("DocUser");
        //当前页数据
        final List<Reservation> list = this.reservationService.selectReserv(doctor.getDoctorId(), page, size);
        //总条数
        final Integer count = this.reservationService.num(doctor.getDoctorId());
        map.put("count", count);
        map.put("res", list);
        return map;
    }

    @GetMapping("/api/reservation/patient")
    public Map<String, Object> selectInfrom(final HttpSession session, final HttpServletRequest request,
                                            @RequestParam(defaultValue = "1") final Integer page,
                                            @RequestParam(defaultValue = "2") final Integer size) {
        final Map<String, Object> map = new HashMap<String, Object>();
        //拿到session
        final Information information = (Information) session.getAttribute("userId");
        //当前页数据
        final List<Reservation> list = this.reservationService.selectResInoform(information.getUserId(), page, size);
        //总条数
        final Integer count = this.reservationService.num(information.getUserId());
        map.put("count", count);
        map.put("res", list);
        return map;
    }

    @PostMapping("/api/reservation/changeStatus")
    public MessageInfo update(@RequestBody Reservation reservation) {
        reservation.setCodeState(reservation.getCodeState() == 0 ? 1 : 0);
        if (this.reservationService.updateCodesate(reservation) == 0) {
            return new MessageInfo(200, "修改失败");
        } else {
            return new MessageInfo(500, "修改成功");
        }
    }

    @PostMapping("/api/reservation/status")
    public MessageInfo update1(@RequestBody Reservation reservation) {
        if (this.reservationService.updatesate(reservation) == 0) {
            return new MessageInfo(200, "修改失败");
        } else {
            return new MessageInfo(500, "修改成功");
        }
    }


}
