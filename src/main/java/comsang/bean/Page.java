package comsang.bean;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class Page {

    private int totalPage;

    private int pageSize;

    private int totalCount;

    private int curr;

    private List<Reservation> list;

}
