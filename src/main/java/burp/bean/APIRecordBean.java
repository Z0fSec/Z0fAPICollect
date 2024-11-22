package burp.bean;

import lombok.Data;

@Data
public class APIRecordBean {
    private Integer id;
    private String method;
    private String url;
    private String request;
    private String response;

    public APIRecordBean() {
    }

    public APIRecordBean(String method, String url, String request, String response) {
        this.method = method;
        this.url = url;
        this.request = request;
        this.response = response;
    }

}
