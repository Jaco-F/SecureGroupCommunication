package utils;

import java.io.Serializable;

/**
 * Created by andre on 12/03/15.
 */
public class TextMessage implements Message,Serializable {
    private byte[] text;

    public TextMessage() {
    }

    public byte[] getText() {
        return text;
    }

    public void setText(byte[] text) {
        this.text = text;
    }
}
