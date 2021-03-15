package comsang.controller;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONObject;
import com.google.gson.Gson;
import comsang.bean.*;
import comsang.config.GMUtil;
import comsang.config.UtilHelper;
import comsang.service.CasesService;
import comsang.service.DoctorService;
import comsang.service.GenerationService;
import comsang.service.InformationService;
import org.springframework.web.bind.annotation.*;

import javax.annotation.Resource;
import javax.servlet.http.HttpServletRequest;
import java.util.*;

@RestController
public class CasesController {

    @Resource
    CasesService casesService;

    @Resource
    DoctorService doctorService;

    @Resource
    InformationService inoformationService;

    @Resource
    GenerationService generationService;


    @PostMapping("/api/medicalRecord")

    public MessageInfo insertCase(@RequestBody Cases cases, final HttpServletRequest request) {

        //SM4加密  参数【（密钥） （需要SM4加密的密文内容）】
        String key = UUID.randomUUID().toString();
        key = key.substring(0, 8) + key.substring(9, 13) + key.substring(14, 18);
        // 分组对称加密，plain长度不足16的倍数的会在plain的前补0，再进行分组加密
        final GMUtil.SM4ECBCipher sm4ECBCipher = GMUtil.sm4EncryptWithECB(key.getBytes(), JSON.toJSONString(cases).getBytes());

        //SM4 密文 sm4ECBCipherHexString
        final String sm4ECBCipherHexString = sm4ECBCipher.toHexString();

        //获取当前登录用户
        final Information information = this.inoformationService.selectById(cases.getInformationId());

        // SM2 用私钥 签名
        // 需要签名的内容
        final byte[] msg = JSON.toJSONString(cases).getBytes();
        // 签名人的userId
        final byte[] userId = cases.getInformationId().toString().getBytes();
        // 得到的SM2签名
        final byte[] sig = GMUtil.signSm3WithSm2(msg, userId, GMUtil.getPrivateKeyFromHex(information.getPrivateKey()));
        System.out.println("签名：" + UtilHelper.byte2Base64StringFun(sig));

        //整合成数据包
        final JSONObject json = new JSONObject();
        json.put("key", key);
        json.put("sm4ECBCipherHexString", sm4ECBCipherHexString);
        json.put("name", UtilHelper.byte2Base64StringFun(sig));
        System.out.println(json);

        //拿对方（医生） 公钥
        final Doctor doctor = (Doctor) request.getSession().getAttribute("DocUser");
        final GMUtil.SM4ECBCipher cipherToDecrypt = new GMUtil.SM4ECBCipher(sm4ECBCipherHexString);
        byte[] bs = cipherToDecrypt.decrypt(key.getBytes());
        final String str = json.toJSONString();
        bs = GMUtil.sm2Encrypt(str.getBytes(), GMUtil.getPublicKeyFromHex(doctor.getDoPublicKey()));
        //存库
        final String end = UtilHelper.byte2Base64StringFun(bs);
        System.out.println(end.length());
        try {
            if (this.casesService.insertCases(cases, end) == 0) {
                return new MessageInfo(200, "失败");
            }
        } catch (final Exception e) {
            return new MessageInfo(200, "异常:" + e.getMessage());
        }
        return new MessageInfo(200, "成功");
    }

    @GetMapping("/api/medicalRecord")
    public MessageInfo selectById(@RequestParam("informationId") final Integer informationId,
                                  @RequestParam(value = "startingTime", required = false) final String startingTime,
                                  @RequestParam(value = "closingTime", required = false) final String closingTime,
                                  final Cases cases, final Information information) {
        final Gson gson = new Gson();
        //SM2解密  参数【（密钥） （需要SM4解密的密文内容）】
        //获取当前患者所有加密后的电子病例
        final List<Generation> list = this.casesService.selectByInId(informationId);
        //SM2解密后数据包
        Map<String, String> decMap = new HashMap<String, String>();
        final List<Cases> caseList = new ArrayList<>();
        for (final Generation generation : list) {
            final Doctor doctor = this.doctorService.getDoctor(this.casesService.selectByToId(generation.getToId()).getDoctorId());
            final byte[] bs = GMUtil.sm2Decrypt(UtilHelper.base64String2ByteFun(generation.getCipherText()), GMUtil.getPrivateKeyFromHex(doctor.getDoPrivateKey()));
            decMap = gson.fromJson(new String(bs), Map.class);


            // SM4 解密
            final GMUtil.SM4ECBCipher cipherToDecrypt = new GMUtil.SM4ECBCipher(decMap.get("sm4ECBCipherHexString"));
            final String key = decMap.get("key");
            // 密钥长度为16字节
            final byte[] bs1 = cipherToDecrypt.decrypt(key.getBytes());
            final String decrypted = new String(bs1);
            System.out.println("SM4 解密获得的原文: " + decrypted);
            final Cases ca = JSONObject.parseObject(decrypted, Cases.class);

            // SM2 用公钥 验签
            final byte[] msg = JSON.toJSONString(ca).getBytes();
            final Information information1 = this.inoformationService.selectById(cases.getInformationId());
            // 验签结果
            final boolean verified = GMUtil.verifySm3WithSm2(msg, cases.getInformationId().toString().getBytes(), UtilHelper.base64String2ByteFun(decMap.get("name")), GMUtil.getPublicKeyFromHex(information1.getPublicKey()));
            System.out.println("签名验证结果：" + verified);
            if (verified) {
                caseList.add(ca);
            }

        }
        return new MessageInfo(200, this.casesService.selectCases(informationId, startingTime, closingTime));
    }
}




