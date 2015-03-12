package utils;

import java.io.Serializable;
import java.net.Socket;

/**
 * Created by andre on 12/03/15.
 */
public class LeaveMessage implements Message,Serializable{
    private Socket source;

    public LeaveMessage(Socket source) {
        this.source = source;
    }

    public Socket getSource() {
        return source;
    }
}
