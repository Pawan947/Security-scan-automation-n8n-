package org.automate.sec;

public class RequestData {

    private String ipaddress;
    private String port;

    public RequestData() {
    }

    public RequestData(String ipaddress, String port) {
        this.ipaddress = ipaddress;
        this.port = port;
    }

    public String getIpaddress() {
        return ipaddress;
    }

    public void setIpaddress(String ipaddress) {
        this.ipaddress = ipaddress;
    }

    public String getPort() {
        return port;
    }

    public void setPort(String port) {
        this.port = port;
    }
}