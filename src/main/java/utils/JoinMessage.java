package utils;

import java.io.Serializable;
import java.security.PublicKey;

/**
 * Created by Jacopo on 11/03/2015.
 */
public class JoinMessage implements Message,Serializable {

    private PublicKey publicKey;

    public JoinMessage(PublicKey publicKey) {
        this.publicKey = publicKey;
    }

    public PublicKey getPublicKey() {
        return publicKey;
    }

}
