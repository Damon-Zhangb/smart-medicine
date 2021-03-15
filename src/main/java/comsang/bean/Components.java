package comsang.bean;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;


@Data
@AllArgsConstructor
@NoArgsConstructor
public class Components {

    private Integer componentsId;

    private Integer organizationId;

    private String componentsName;

    private Integer networkId;

    private Integer type;

    private String domainName;

    private String port;

    private String ip;

    private String healthCheckPort;

    private Health healthCheck;


}
