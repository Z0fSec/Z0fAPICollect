package burp.bean;

import lombok.Getter;
import lombok.Setter;

@Setter
@Getter
public class ZacConfigBean {
    private int id;
    private String type;
    private String value;

    public ZacConfigBean() {
    }

    public ZacConfigBean(String type, String value) {
        this.type = type;
        this.value = value;
    }

}
