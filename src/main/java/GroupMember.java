import utils.JoinMessage;
import utils.Message;
import utils.ServerJoinKeys;
import utils.TextMessage;

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.net.ServerSocket;
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

    private ServerSocket listeningSocket;

    private Socket serverSocket;
    private String address;
    private int port;

    private Cipher desCipher;
    private Cipher rsaCipher;


    public GroupMember(String ip, int port) {
        this.port = port;
        this.address = ip;
        kek = new SecretKey[3];
        try {
            listeningSocket = new ServerSocket(port);
        } catch (IOException e) {
            e.printStackTrace();
        }
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

        try {
            serverSocket = new Socket("localhost",12000);
        } catch (IOException e) {
            e.printStackTrace();
        }

    }

    @Override
    public void run() {
        join();
        Thread writeThread = new Thread(new WriteChat(this));
        writeThread.start();
        Socket senderSocket;

        Message inputMsg;
        ObjectInputStream objectInputStream;

        while (true){
            try {
                senderSocket = listeningSocket.accept();
                objectInputStream = new ObjectInputStream(senderSocket.getInputStream());
                inputMsg = (Message)objectInputStream.readObject();

                if(inputMsg.getClass().getName().equals("utils.ServerJoinKeys")){
                    System.out.println("Another client is in the group");
                    ServerJoinKeys serverJoinKeys = (ServerJoinKeys) inputMsg;

                    //DECRYPT DEK
                    byte[] decDek;
                    try {
                        desCipher.init(Cipher.DECRYPT_MODE,dek);
                        decDek = desCipher.doFinal(serverJoinKeys.getDek());
                        dek = new SecretKeySpec(decDek,0,decDek.length,"DES");
                    } catch (BadPaddingException e) {
                        System.out.println("Error in dek decryption");
                    }

                    //DECRYPT KEK1
                    byte[] decKek;
                    try {
                        desCipher.init(Cipher.DECRYPT_MODE,kek[0]);
                        decKek = desCipher.doFinal(serverJoinKeys.getKek1());
                        kek[0] = new SecretKeySpec(decKek,0,decKek.length,"DES");
                    } catch (BadPaddingException e) {
                        System.out.println("I don't need the kek 1");
                    }

                    //DECRYPT KEK2
                    try {
                        desCipher.init(Cipher.DECRYPT_MODE,kek[1]);
                        decKek = desCipher.doFinal(serverJoinKeys.getKek2());
                        kek[1] = new SecretKeySpec(decKek,0,decKek.length,"DES");
                    } catch (BadPaddingException e) {
                        System.out.println("I don't need the kek 2");
                    }

                    //DECRYPT KEK3
                    try {
                        desCipher.init(Cipher.DECRYPT_MODE,kek[2]);
                        decKek = desCipher.doFinal(serverJoinKeys.getKek3());
                        kek[2] = new SecretKeySpec(decKek,0,decKek.length,"DES");
                    } catch (BadPaddingException e) {
                        System.out.println("I don't need the kek 3");
                    }

                }else if (inputMsg.getClass().getName().equals("utils.TextMessage")){
                    TextMessage txMessage = (TextMessage) inputMsg;
                    desCipher.init(Cipher.DECRYPT_MODE,dek);
                    try {
                        byte [] decMsg = desCipher.doFinal(txMessage.getText());
                        String msg = new String(decMsg);
                        System.out.println(txMessage.getAddress() + " - " + txMessage.getPort() + " : " + msg);
                    } catch (BadPaddingException e) {
                        e.printStackTrace();
                    }
                }

            } catch (IOException | ClassNotFoundException | IllegalBlockSizeException | InvalidKeyException e) {
                e.printStackTrace();
            }
        }

    }

    private void join(){
        Message message = new JoinMessage(publicKey,this.address, this.port);
        ObjectOutputStream objectOutputStream = null;
        ObjectInputStream objectInputStream = null;

        ServerJoinKeys initMessage = null;

        Socket senderSocket;

        //------------------------------------------------------
        //CONNECT TO THE SERVER AND SEND HIM THE JOIN MESSAGE
        //------------------------------------------------------
        try {
            objectOutputStream = new ObjectOutputStream(serverSocket.getOutputStream());
        } catch (IOException e) {
            System.out.println("Cannot create objectOutputStream");
            e.printStackTrace();
        }

        try {
            objectOutputStream.writeObject(message);
            System.out.println("Message to join the group sent");
        } catch (IOException e) {
            System.out.println("Cannot write object to group master");
            e.printStackTrace();
        }

        //-----------------------------------------------------
        //WAIT FOR THE SERVER RESPONSE
        //-----------------------------------------------------

        try {
            senderSocket = listeningSocket.accept();
            objectInputStream = new ObjectInputStream(senderSocket.getInputStream());
            initMessage = (ServerJoinKeys)objectInputStream.readObject();
        } catch (IOException | ClassNotFoundException e) {
            e.printStackTrace();
        }


        System.out.println("Message with keks and dek Received");
        try {
            rsaCipher.init(Cipher.DECRYPT_MODE,privateKey);
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        }

        //DECRYPTS AND SAVE DEK
        try {
            byte[] decDek = rsaCipher.doFinal(initMessage.getDek());
            dek = new SecretKeySpec(decDek,0,decDek.length,"DES");
        } catch (IllegalBlockSizeException | BadPaddingException e) {
            System.out.println("Error in dek decryption");
            e.printStackTrace();
        }

        //DECRYPTS AND SAVE KEKs
        try {
            byte[] decKek1 = rsaCipher.doFinal(initMessage.getKek1());
            byte[] decKek2 = rsaCipher.doFinal(initMessage.getKek2());
            byte[] decKek3 = rsaCipher.doFinal(initMessage.getKek3());
            kek[0] = new SecretKeySpec(decKek1,0,decKek1.length,"DES");
            kek[1] = new SecretKeySpec(decKek2,0,decKek2.length,"DES");
            kek[2] = new SecretKeySpec(decKek3,0,decKek3.length,"DES");
        } catch (IllegalBlockSizeException|BadPaddingException e){
            System.out.println("Error in kek decryption");
            e.printStackTrace();
        }
        System.out.println("Keks and Dek saved");

        try {
            objectInputStream.close();
            objectOutputStream.close();
            serverSocket.close();
        } catch (IOException e) {
            e.printStackTrace();
        }

    }

    public void sendMsg(String msg){
        ObjectOutputStream objectOutputStream = null;
        TextMessage txMessage = new TextMessage();
        txMessage.setAddress(address);
        txMessage.setPort(port);
        try {
            serverSocket = new Socket("localhost",12000);
        } catch (IOException e) {
            e.printStackTrace();
        }
        try {
            desCipher.init(Cipher.ENCRYPT_MODE,dek);
            byte[] msgEnc = desCipher.doFinal(msg.getBytes());
            txMessage.setText(msgEnc);
        } catch (InvalidKeyException | IllegalBlockSizeException | BadPaddingException e) {
            e.printStackTrace();
        }

        try {
            objectOutputStream = new ObjectOutputStream(serverSocket.getOutputStream());
        } catch (IOException e) {
            System.out.println("Cannot create objectOutputStream");
            e.printStackTrace();
        }

        try {
            objectOutputStream.writeObject(txMessage);
        } catch (IOException e) {
            System.out.println("Cannot write object to group master");
            e.printStackTrace();
        }
    }
}

class WriteChat implements Runnable{

    private GroupMember groupMember;

    public WriteChat(GroupMember groupMember){
        this.groupMember = groupMember;
    }

    @Override
    public void run() {
        //liSTEN FOR KEYBOARD INPUT
        String line="";
        while(true){

            BufferedReader br = new BufferedReader(new InputStreamReader(System.in));
            System.out.println("Type the message to broadcast (exit to leave)...");
            try {
                line = br.readLine();
            } catch (IOException e) {
                e.printStackTrace();
            }
            if(line.equals("exit")){
                //Todo:chiamare leave
            }
            else{
                groupMember.sendMsg(line);
            }
        }
    }
}
