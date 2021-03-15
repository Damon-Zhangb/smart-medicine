package comsang.bean;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class Organization {

    private int organizationId;

    private String organizationName;

    private List<Components> components;

}
