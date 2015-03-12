package utils;

import java.io.Serializable;
import java.net.Socket;

/**
 * Created by andre on 12/03/15.
 */
public class LeaveMessage implements Message,Serializable{
    private int port;
    private String address;

    public LeaveMessage(int port, String address) {
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
