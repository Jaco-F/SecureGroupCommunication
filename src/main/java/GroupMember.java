import utils.JoinMessage;
import utils.Message;
import utils.ServerInitMessage;

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutput;
import java.io.ObjectOutputStream;
import java.net.Socket;
import java.security.*;

/**
 * Created by Jacopo on 11/03/2015.
 */
public class GroupMember implements Runnable{
    private PrivateKey privateKey;
    private PublicKey publicKey;

    private SecretKey dek;
    private SecretKey[] kek;

    private Socket mySocket;

    private Cipher desCipher;
    private Cipher rsaCipher;


    public GroupMember() {

        //-----------------------------------------
        //GENERATE PUBLIC AND PRIVATE KEY
        //-----------------------------------------
        KeyPairGenerator keyPairGenerator;
        try {
            keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(1024);
            KeyPair keyPair = keyPairGenerator.genKeyPair();
            privateKey = keyPair.getPrivate();
            publicKey = keyPair.getPublic();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }

        try {
            desCipher = Cipher.getInstance("DES");
        } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
            e.printStackTrace();
        }

        try {
            rsaCipher = Cipher.getInstance("RSA");
        } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
            e.printStackTrace();
        }

    }

    @Override
    public void run() {

        while (true){

        }

    }

    private void join(){
        Socket socket = null;
        Message message = new JoinMessage(publicKey,mySocket);
        ObjectOutputStream objectOutputStream = null;
        ObjectInputStream objectInputStream = null;

        ServerInitMessage initMessage = null;

        //------------------------------------------------------
        //CONNECT TO THE SERVER AND SEND HIM THE JOIN MESSAGE
        //------------------------------------------------------
        try {
            socket = new Socket("localhost",2345);
        } catch (IOException e) {
            System.out.println("Cannot create socket");
            e.printStackTrace();
        }

        try {
            objectOutputStream = new ObjectOutputStream(socket.getOutputStream());
        } catch (IOException e) {
            System.out.println("Cannot create objectOutputStream");
            e.printStackTrace();
        }

        try {
            objectOutputStream.writeObject(message);
        } catch (IOException e) {
            System.out.println("Cannot write object to group master");
            e.printStackTrace();
        }

        //-----------------------------------------------------
        //WAIT FOR THE SERVER RESPONSE
        //-----------------------------------------------------

        try {
            initMessage = (ServerInitMessage)objectInputStream.readObject();
        } catch (IOException | ClassNotFoundException e) {
            e.printStackTrace();
        }

        try {
            rsaCipher.init(Cipher.DECRYPT_MODE,privateKey);
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        }

        //DECRYPTS AND SAVE DEK
        try {
            byte[] decDek = rsaCipher.doFinal(initMessage.getDek());
            dek = new SecretKeySpec(decDek,0,decDek.length,"RSA");
        } catch (IllegalBlockSizeException | BadPaddingException e) {
            System.out.println("Error in dek decryption");
            e.printStackTrace();
        }

        //DECRYPTS AND SAVE KEKs
        try {
            byte[] decKek1 = rsaCipher.doFinal(initMessage.getKek1());
            byte[] decKek2 = rsaCipher.doFinal(initMessage.getKek2());
            byte[] decKek3 = rsaCipher.doFinal(initMessage.getKek3());
            kek[0] = new SecretKeySpec(decKek1,0,decKek1.length,"RSA");
            kek[1] = new SecretKeySpec(decKek2,0,decKek2.length,"RSA");
            kek[2] = new SecretKeySpec(decKek3,0,decKek3.length,"RSA");
        } catch (IllegalBlockSizeException|BadPaddingException e){
            System.out.println("Error in kek decryption");
            e.printStackTrace();
        }

    }
}
