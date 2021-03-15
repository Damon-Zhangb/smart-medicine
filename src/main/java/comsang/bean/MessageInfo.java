package comsang.bean;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class MessageInfo {

    private Integer returnCode;
    private String msg;
    private Object data;

    public MessageInfo(final Integer returnCode, final Object data) {
        this.returnCode = returnCode;
        this.data = data;
    }

    public MessageInfo(final Integer returnCode, final String msg) {
        this.returnCode = returnCode;
        this.msg = msg;
    }

}


