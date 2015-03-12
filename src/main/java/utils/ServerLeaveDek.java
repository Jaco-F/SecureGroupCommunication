package utils;

/**
 * Created by andre on 12/03/15.
 */
public class ServerLeaveDek {
    byte[] dek;

    public ServerLeaveDek(byte[] dek) {
        this.dek = dek;
    }

    public ServerLeaveDek() {
    }

    public byte[] getDek() {
        return dek;
    }

    public void setDek(byte[] dek) {
        this.dek = dek;
    }
}
