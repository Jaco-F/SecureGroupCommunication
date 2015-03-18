package utils;

import java.io.Serializable;

/**
 * Created by andre on 12/03/15.
 */
public class TextMessage implements Message,Serializable{
    private byte[] text;
    private String hostName;


    public TextMessage() {
    }

    public String getHostName() {
        return hostName;
    }

    public void setHostName(String hostName) {
        this.hostName = hostName;
    }

    public byte[] getText() {
        return text;
    }

    public void setText(byte[] text) {
        this.text = text;
    }

}
