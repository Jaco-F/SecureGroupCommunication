package utils;

import java.io.Serializable;
import java.net.Socket;
import java.security.PublicKey;

/**
 * Created by Jacopo on 11/03/2015.
 */
public class JoinMessage implements Message,Serializable {

    private PublicKey publicKey;
    private Socket source;

    public JoinMessage(PublicKey publicKey, Socket source) {
        this.publicKey = publicKey;
        this.source = source;
    }

    public PublicKey getPublicKey() {
        return publicKey;
    }

    public Socket getSource() {
        return source;
    }
}
