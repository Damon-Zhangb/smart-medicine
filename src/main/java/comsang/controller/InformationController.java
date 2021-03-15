package comsang.controller;

import comsang.bean.Information;
import comsang.bean.MessageInfo;
import comsang.config.GMUtil;
import comsang.config.MD5;
import comsang.service.InformationService;
import org.springframework.web.bind.annotation.*;

import javax.annotation.Resource;
import javax.servlet.http.HttpSession;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.regex.Pattern;


@RestController
public class InformationController {

    @Resource
    InformationService informationService;

    @PostMapping("/api/patient/register")
    public MessageInfo insert(@RequestBody Information information) {
        // 非空判断
        if (information.getUserPassword() == null || information.getUserSex() == null
                || information.getUserName() == null || information.getAge() == null
                || information.getIdNumber() == null || information.getNation() == null
                || information.getMarriage() == null || information.getNativePlace() == null
                || information.getPhoneNumber() == null) {
            return new MessageInfo(500, "字段未填写完整！请补充！");
        }
        if (!Pattern.matches("^((17[0-9])|(14[0-9])|(13[0-9])|(15[^4,\\D])|(18[0,5-9]))\\d{8}$", information.getPhoneNumber())) {
            return new MessageInfo(500, "账号格式不对！");
        }
        if (this.informationService.loginInformation(information.getPhoneNumber()) != null) {
            return new MessageInfo(500, "该账号已存在！");
        }

        //公si
        final KeyPair keyPair = GMUtil.generateKeyPair();
        final PrivateKey privateKey = keyPair.getPrivate();
        final PublicKey publicKey = keyPair.getPublic();
        information.setPrivateKey(GMUtil.getPrivateKeyHex(privateKey));
        information.setPublicKey(GMUtil.getPublicKeyHex(publicKey));
        information.setUserPassword(MD5.getMD5Code(information.getUserPassword()));
        try {
            if (this.informationService.insertInformation(information) == 0) {
                return new MessageInfo(501, "失败");
            }
        } catch (final Exception e) {
            return new MessageInfo(502, "异常:" + e.getMessage());
        }
        return new MessageInfo(200, "成功");
    }


    @RequestMapping("/api/patient/login")
    public MessageInfo test1(@RequestParam("telephone") final String telephone,
                             @RequestParam("password") final String password,
                             final HttpSession session) {
        if (!Pattern.matches("^((17[0-9])|(14[0-9])|(13[0-9])|(15[^4,\\D])|(18[0,5-9]))\\d{8}$", telephone)) {
            return new MessageInfo(500, "账号格式不对！");
        }
        final String md5Code = MD5.getMD5Code(password);
        final Information user = this.informationService.loginInformation(telephone);
        if (user != null) {
            if (user.getUserPassword().equals(md5Code)) {
                //放到session
                session.setAttribute("userId", user);
                return new MessageInfo(200, "登录成功！", user);
            }
            return new MessageInfo(500, "账号或者密码错误！!");
        }
        return new MessageInfo(500, "无此账号！");

    }

    @GetMapping("/api/information")
    public MessageInfo selectById(@RequestParam("userId") final Integer userId) {
        return new MessageInfo(200, this.informationService.selectDetails(userId));
    }


}
