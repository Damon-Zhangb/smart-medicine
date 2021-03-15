package comsang.service;

import comsang.bean.*;
import comsang.config.UtilHelper;
import comsang.mapper.CasesMapper;
import comsang.mapper.GenerationMapper;
import comsang.mapper.InformationMapper;
import comsang.mapper.ReservationMapper;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import java.util.List;

@SpringBootTest
public class IbatisUpdate {

    @Autowired
    private AotoService aotoService;

    @Autowired
    private CasesMapper casesMapper;

    @Autowired
    private InformationMapper informationMapper;

    @Autowired
    private ReservationMapper reservationMapper;

    @Autowired
    private GenerationMapper generationMapper;


    /**
     * aoto查询
     */
    @Test
    public void aotoSelect() {
        List<Aoto> aotos = aotoService.selectAoto();
        aotos.forEach(System.out::println);
    }

    /**
     * 病历信息插入
     */
    @Test
    public void casesInsert() {
        Cases cases = new Cases();
        cases.setTime("2020-8-27");
        cases.setHospital("人民医院");
        cases.setAotoId(1);
        cases.setDepartment("骨科");
        cases.setOddNumbers("112233");
        cases.setMainSuit("骨折");
        cases.setInformationId(1);
        cases.setDoctorId(1);
        cases.setIllnessHistory("无");
        cases.setFamily("无");
        cases.setBuild("不知道");
        cases.setAssist("也不知道");
        cases.setMedicine("止痛药");
        cases.setTcms("还是不知道");
        casesMapper.insertCases(cases);
    }

    /**
     * 患者信息插入
     */
    @Test
    public void infoInsert() {
        Information information = new Information();
        information.setUserName("张三");
        information.setUserPassword("123456");
        information.setUserSex(1);
        information.setAge(18);
        information.setAddress("河南");
        information.setNation("汉");
        information.setGrave("有");
        information.setIdNumber("42103937495748");
        information.setMarriage("已婚");
        information.setNativePlace("濮阳");
        information.setPhoneNumber("12345678901");
        information.setPrivateKey("不知道");
        information.setPublicKey("知道");
        informationMapper.insertInformation(information);
    }

    /**
     * 患者信息查询byPhone
     */
    @Test
    public void infoSelectByPhone() {
        Information information = informationMapper.loginInformation("12345678901");
        System.out.println(information);
    }

    /**
     * 患者信息查询byId
     */
    @Test
    public void infoSelectById() {
        Information information = informationMapper.selectById(1);
        System.out.println(information);
    }

    /**
     * 患者部分信息查询byId
     */
    @Test
    public void infoSelectById2() {
        List<Information> informations = informationMapper.selectDetails(1);
        informations.forEach(System.out::println);
    }

    /**
     * 预订单插入
     */
    @Test
    public void reseInsert() {
        Reservation reservation = new Reservation();
        reservation.setPatientId(1);
        reservation.setDoctorId(1);
        reservation.setAotoId(1);
        reservation.setReservationTime("2020-8-20");
        reservation.setCost(100);
        reservation.setReservationStatus(1);
        reservation.setReservationNumber(123);
        reservation.setAuthorizationCode("123");
        reservation.setCodeState(200);
        reservationMapper.insertReservation(reservation);
    }

    /**
     * 医生查看预约单
     */
    @Test
    public void reseSelectByDoctor() {
        List<Reservation> reservations = reservationMapper.selectReserv(1, 0, 1);
        reservations.forEach(System.out::println);
    }

    /**
     * 患者查看预约单
     */
    @Test
    public void reseSelectByUser() {
        List<Reservation> reservations = reservationMapper.selectResInoform(1, 0, 1);
        reservations.forEach(System.out::println);
    }

    /**
     * gene插入
     */
    @Test
    public void geneInsert() {
        Generation generation = new Generation();
        generation.setToId(1);
        generation.setCipherText("不准备不知道");
        generationMapper.insert(generation);
    }

    @Test
    public void text1() {
        UtilHelper utilHelper = new UtilHelper();
        byte[] funs = UtilHelper.base64String2ByteFun("8542D69E4C044F18E8B92435BF6FF7DE457283915C45517D722EDB8B08F1DFC3");
        for (byte fun : funs) {
            System.out.println(fun);
        }
    }

    @Test
    public void tet2() {
        Reservation reservation = new Reservation();
        reservation.setReservationId(6);
        reservation.setCodeState(212);
        int is = reservationMapper.updateCodesate(reservation);

    }

} 