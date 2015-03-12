package utils;

import java.io.Serializable;

/**
 * Created by andre on 12/03/15.
 */
public class ServerLeaveKek implements Message,Serializable{
    private byte[] kek1;
    private byte[] kek2;
    private byte[] kek3;

    public ServerLeaveKek() {
    }

    public byte[] getKek1() {
        return kek1;
    }

    public void setKek1(byte[] kek1) {
        this.kek1 = kek1;
    }

    public byte[] getKek2() {
        return kek2;
    }

    public void setKek2(byte[] kek2) {
        this.kek2 = kek2;
    }

    public byte[] getKek3() {
        return kek3;
    }

    public void setKek3(byte[] kek3) {
        this.kek3 = kek3;
    }
}
