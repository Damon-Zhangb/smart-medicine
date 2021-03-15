package comsang.controller;

import comsang.bean.Doctor;
import comsang.bean.MessageInfo;
import comsang.config.MD5;
import comsang.service.DoctorService;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import javax.annotation.Resource;
import javax.servlet.http.HttpSession;

@RestController
public class DoctorController {
    @Resource
    DoctorService doctorService;

    @RequestMapping("/api/doctor/login")
    public MessageInfo test1(@RequestParam("doctorNoba") final String doctorNoba,
                             @RequestParam("doctorPassword") final String doctorPassword,
                             final HttpSession session) {
        final String md5Code = MD5.getMD5Code(doctorPassword);
        System.out.println(md5Code);
        final Doctor user = this.doctorService.doctorlogin(doctorNoba, doctorPassword);
        if (user != null) {
            if (user.getDoctorPassword().equals(md5Code)) {
                //放到session
                session.setAttribute("DocUser", user);
                return new MessageInfo(200, "登陆成功！", user);
            }
            return new MessageInfo(500, "账号或者密码错误！！");
        }
        return new MessageInfo(500, "无此账号！");
    }

    @GetMapping("/api/doctor")
    public MessageInfo selectById(@RequestParam("aotoId") final Integer aotoId) {
        return new MessageInfo(200, this.doctorService.selectDoctor(aotoId));
    }
}
