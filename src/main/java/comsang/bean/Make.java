package comsang.bean;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class Make {

    private Integer makeId;

    private Integer doctorId;

    private String makeTime;

}
