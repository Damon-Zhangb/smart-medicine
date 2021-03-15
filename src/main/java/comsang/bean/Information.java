package comsang.bean;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class Information {

    private Integer userId;

    private String userName;

    private String userPassword;

    private Integer userSex;

    private Integer age;

    private String idNumber;

    private String nation;

    private String marriage;

    private String nativePlace;

    private String phoneNumber;

    private String address;

    private String privateKey;

    private String publicKey;

    private String grave;

}
