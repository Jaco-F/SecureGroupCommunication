package utils;

import java.io.Serializable;

/**
 * Created by andre on 12/03/15.
 */
public class TextMessage implements Message,Serializable{
    byte[] text;
    String address;
    int port;

    public TextMessage() {
    }

    public byte[] getText() {
        return text;
    }

    public void setText(byte[] text) {
        this.text = text;
    }

    public String getAddress() {
        return address;
    }

    public void setAddress(String address) {
        this.address = address;
    }

    public int getPort() {
        return port;
    }

    public void setPort(int port) {
        this.port = port;
    }
}
