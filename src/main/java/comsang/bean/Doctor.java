package comsang.bean;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class Doctor {

    private Integer doctorId;

    private Integer aotoId;

    private Integer gender;

    private String doctorName;

    private String doctorNumber;

    private String doctorPassword;

    private String doPrivateKey;

    private String doPublicKey;


}
