package utils;

import java.io.Serializable;

/**
 * Created by Jacopo on 11/03/2015.
 */
public class ServerInitMessage implements Message,Serializable {
    byte[] dek;
    byte[] kek1;
    byte[] kek2;
    byte[] kek3;

    public ServerInitMessage(byte[] dek, byte[] kek1, byte[] kek2, byte[] kek3) {
        this.dek = dek;
        this.kek1 = kek1;
        this.kek2 = kek2;
        this.kek3 = kek3;
    }

    public byte[] getDek() {
        return dek;
    }

    public byte[] getKek1() {
        return kek1;
    }

    public byte[] getKek2() {
        return kek2;
    }

    public byte[] getKek3() {
        return kek3;
    }
}
