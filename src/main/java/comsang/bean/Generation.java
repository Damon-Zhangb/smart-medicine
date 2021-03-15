package comsang.bean;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class Generation {

    private Integer cipId;
    private Integer toId;
    private String cipherText;


}
