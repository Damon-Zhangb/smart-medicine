package comsang.bean;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class Network {

    private Integer networkId;

    private String networkName;

    private String introduction;

    private String version;

    private Integer consensusType;

    private String createDate;

    private List<Components> orgs;

}
