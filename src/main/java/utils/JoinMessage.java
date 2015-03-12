package utils;

import java.io.Serializable;
import java.security.PublicKey;

/**
 * Created by Jacopo on 11/03/2015.
 */
public class JoinMessage implements Message,Serializable {

    private PublicKey publicKey;
    private String sourceIP;
    private int sourcePort;

    public JoinMessage(PublicKey publicKey, String sourceIP, int sourcePort) {
        this.publicKey = publicKey;
        this.sourceIP = sourceIP;
        this.sourcePort = sourcePort;
    }

    public PublicKey getPublicKey() {
        return publicKey;
    }

    public String getSourceIP() {
        return sourceIP;
    }

    public int getSourcePort() {
        return sourcePort;
    }
}
