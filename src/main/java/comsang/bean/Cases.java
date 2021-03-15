package comsang.bean;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class Cases {

    private Integer caseId;

    private String time;

    private String hospital;

    private Integer aotoId;

    private String department;

    private String oddNumbers;

    private String mainSuit;

    private Integer informationId;

    private String illnessHistory;

    private String family;

    private String build;

    private String assist;

    private String medicine;

    private String tcms;

    private String handle;

    private Information info;

    private Integer doctorId;

}
