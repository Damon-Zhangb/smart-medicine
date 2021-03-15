package comsang.bean;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.UUID;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class Reservation {
    private Integer reservationId;
    private Integer patientId;
    private Integer doctorId;
    private Integer aotoId;
    private String reservationTime;
    private Integer cost;
    private Integer reservationStatus;
    private String authorizationCode;
    private Integer codeState;
    private Integer reservationNumber;
    private String doctorName;
    private String userName;
    private String aotoName;
    private Integer gender;
    private Integer reservationSex;
    private String key;

    public String getKey() {
        return this.key;
    }

    public static void setKey(String key) {
        //16位key （密钥）
        key = UUID.randomUUID().toString();
        key = key.substring(0, 8) + key.substring(9, 13) + key.substring(14, 18);
    }


}
