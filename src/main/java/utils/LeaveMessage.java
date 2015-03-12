package utils;

import java.io.Serializable;

/**
 * Created by andre on 12/03/15.
 */
public class LeaveMessage implements Message,Serializable{
    private int port;
    private String address;

    public LeaveMessage(String address,int port) {
        this.port = port;
        this.address = address;
    }

    public int getPort() {
        return port;
    }

    public String getAddress() {
        return address;
    }
}
