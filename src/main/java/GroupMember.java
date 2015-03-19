import utils.*;

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.net.*;
import java.security.*;

/**
 * Created by Jacopo? on 11/03/2015.
 */
public class GroupMember implements Runnable{
    private PrivateKey privateKey;
    private PublicKey publicKey;

    private SecretKey dek;
    private SecretKey[] keks;

    private MulticastSocket listeningSocket;
    private Socket serverSocket;
    private ServerSocket clientSocket;
    private int port;

    private Cipher desCipher;
    private Cipher rsaCipher;

    private final String serverAddress = "192.168.0.2";
    private final int SERVER_PORT = 13000;
    private final int CLIENT_PORT = 14000;
    private final int MONITORING_PORT = 15000;
    private  String hostName ="";

    private String groupAddress = "239.0.0.1";

    private Thread monitoringThread;

    private boolean joined;

    public GroupMember(int port) {
        this.port = port;
        keks = new SecretKey[3];

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
        //join();
        joined = false;
        try {
            listeningSocket = new MulticastSocket(port);
            InetAddress address = InetAddress.getByName(groupAddress);
            hostName = Inet4Address.getLocalHost().getHostName();
            listeningSocket.joinGroup(address);
        } catch (IOException e) {
            e.printStackTrace();
        }

        Thread writeThread = new Thread(new WriteChat(this));
        writeThread.start();

        Message inputMsg;
        ObjectInputStream objectInputStream;


        while (true){
            try {

                byte[] b = new byte[65535];
                ByteArrayInputStream bis = new ByteArrayInputStream(b);
                DatagramPacket dgram = new DatagramPacket(b, b.length);
                listeningSocket.receive(dgram);

                objectInputStream = new ObjectInputStream(bis);
                inputMsg = (Message)objectInputStream.readObject();

                if (joined) {
                    if (inputMsg instanceof ServerJoinKeys) {
                        System.out.println("Another client is in the group");
                        ServerJoinKeys serverJoinKeys = (ServerJoinKeys) inputMsg;

                        //DECRYPT DEK
                        byte[] decDek;
                        try {
                            desCipher.init(Cipher.DECRYPT_MODE, dek);
                            decDek = desCipher.doFinal(serverJoinKeys.getDek());
                            dek = new SecretKeySpec(decDek, 0, decDek.length, "DES");
                        } catch (BadPaddingException e) {
                            System.out.println("Error in dek decryption");
                        }

                        //DECRYPT KEK1
                        byte[] decKek;
                        try {
                            desCipher.init(Cipher.DECRYPT_MODE, keks[0]);
                            decKek = desCipher.doFinal(serverJoinKeys.getKek1());
                            keks[0] = new SecretKeySpec(decKek, 0, decKek.length, "DES");
                        } catch (BadPaddingException e) {
                            System.out.println("I don't need the kek 1");
                        }

                        //DECRYPT KEK2
                        try {
                            desCipher.init(Cipher.DECRYPT_MODE, keks[1]);
                            decKek = desCipher.doFinal(serverJoinKeys.getKek2());
                            keks[1] = new SecretKeySpec(decKek, 0, decKek.length, "DES");
                        } catch (BadPaddingException e) {
                            System.out.println("I don't need the kek 2");
                        }

                        //DECRYPT KEK3
                        try {
                            desCipher.init(Cipher.DECRYPT_MODE, keks[2]);
                            decKek = desCipher.doFinal(serverJoinKeys.getKek3());
                            keks[2] = new SecretKeySpec(decKek, 0, decKek.length, "DES");
                        } catch (BadPaddingException e) {
                            System.out.println("I don't need the kek 3");
                        }

                    } else if (inputMsg instanceof TextMessage) {
                        TextMessage txMessage = (TextMessage) inputMsg;
                        desCipher.init(Cipher.DECRYPT_MODE, dek);
                        try {
                            byte[] decMsg = desCipher.doFinal(txMessage.getText());
                            String msg = new String(decMsg);
                            System.out.println("#SecureChannel : " + txMessage.getHostName() + " : " + msg);
                        } catch (BadPaddingException | IllegalBlockSizeException e) {
                            System.out.println(txMessage.getHostName() + ":" + new String(txMessage.getText()));
                        }

                    } else if (inputMsg instanceof ServerLeaveDek) {
                        ServerLeaveDek serverLeaveDek = (ServerLeaveDek) inputMsg;
                        byte[] decDek;

                        //I NEED TO TRY WITH ALL MY KEKS IF I CAN DECRYPT THE MESSAGE
                        //THIS WAY I CAN OBTAIN THE NEW DEK
                        for (SecretKey kek : keks) {
                            try {
                                desCipher.init(Cipher.DECRYPT_MODE, kek);
                                decDek = desCipher.doFinal(serverLeaveDek.getDek());
                                dek = new SecretKeySpec(decDek, 0, decDek.length, "DES");
                            } catch (BadPaddingException e) {
                                //System.out.println("");
                            }
                        }
                    } else if (inputMsg instanceof ServerLeaveKek) {
                        ServerLeaveKek serverLeaveKek = (ServerLeaveKek) inputMsg;
                        byte[] firstPhaseDecriptedKek;
                        byte[] decKek;
                        try {
                            desCipher.init(Cipher.DECRYPT_MODE, dek);
                            firstPhaseDecriptedKek = desCipher.doFinal(serverLeaveKek.getKek1());
                            desCipher.init(Cipher.DECRYPT_MODE, keks[0]);
                            decKek = desCipher.doFinal(firstPhaseDecriptedKek);
                            keks[0] = new SecretKeySpec(decKek, 0, decKek.length, "DES");
                        } catch (BadPaddingException e) {
                            System.out.println("I don't need kek 1");
                        }
                        try {
                            desCipher.init(Cipher.DECRYPT_MODE, dek);
                            firstPhaseDecriptedKek = desCipher.doFinal(serverLeaveKek.getKek2());
                            desCipher.init(Cipher.DECRYPT_MODE, keks[1]);
                            decKek = desCipher.doFinal(firstPhaseDecriptedKek);
                            keks[1] = new SecretKeySpec(decKek, 0, decKek.length, "DES");
                        } catch (BadPaddingException e) {
                            System.out.println("I don't need kek 2");
                        }
                        try {
                            desCipher.init(Cipher.DECRYPT_MODE, dek);
                            firstPhaseDecriptedKek = desCipher.doFinal(serverLeaveKek.getKek3());
                            desCipher.init(Cipher.DECRYPT_MODE, keks[2]);
                            decKek = desCipher.doFinal(firstPhaseDecriptedKek);
                            keks[2] = new SecretKeySpec(decKek, 0, decKek.length, "DES");
                        } catch (BadPaddingException e) {
                            System.out.println("I don't need kek 3");
                        }
                    }
                }
                else {
                    if (inputMsg instanceof TextMessage){
                        TextMessage txMessage = (TextMessage) inputMsg;
                        String msg = new String(txMessage.getText());
                        System.out.println(txMessage.getHostName() + " : " + msg);
                    }
                }
            } catch (IOException | ClassNotFoundException | IllegalBlockSizeException | InvalidKeyException e) {
                e.printStackTrace();
            }
        }

    }

    private void join(){
        //------------------------------------------------------
        //INIT SOCKETs AND CIPHERs
        //------------------------------------------------------

        Message message = new JoinMessage(publicKey);
        ObjectOutputStream objectOutputStream = null;
        ObjectInputStream objectInputStream = null;
        ServerJoinKeys initMessage = null;

        monitoringThread = new Thread(new GroupMemberChecker());


        try {
            //Sockets init
            clientSocket = new ServerSocket(CLIENT_PORT);
            serverSocket = new Socket(serverAddress,SERVER_PORT);

        } catch (IOException e) {
            e.printStackTrace();
        }

        try {
            rsaCipher.init(Cipher.DECRYPT_MODE,privateKey);
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        }


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

        Socket server = null;
        try {
            server = clientSocket.accept();
            objectInputStream = new ObjectInputStream(server.getInputStream());

            initMessage = (ServerJoinKeys)objectInputStream.readObject();
        } catch (IOException | ClassNotFoundException e) {
            e.printStackTrace();
        }


        System.out.println("Message with keks and dek Received");


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
            keks[0] = new SecretKeySpec(decKek1,0,decKek1.length,"DES");
            keks[1] = new SecretKeySpec(decKek2,0,decKek2.length,"DES");
            keks[2] = new SecretKeySpec(decKek3,0,decKek3.length,"DES");
        } catch (IllegalBlockSizeException|BadPaddingException e){
            System.out.println("Error in kek decryption");
            e.printStackTrace();
        }
        System.out.println("Keks and Dek saved");

        try {
            objectInputStream.close();
            objectOutputStream.close();
            serverSocket.close();
            clientSocket.close();
        } catch (IOException e) {
            e.printStackTrace();
        }

        monitoringThread.start();
        joined = true;
    }

    private void broadcastMessage(String msg) {
        ObjectOutputStream objectOutputStream = null;
        TextMessage txMessage = new TextMessage();

        try {
            txMessage.setHostName(hostName);
            if(!joined){
                txMessage.setText(msg.getBytes());
            }
            else {
                try {
                    desCipher.init(Cipher.ENCRYPT_MODE, dek);
                    byte[] msgEnc = desCipher.doFinal(msg.getBytes());
                    txMessage.setText(msgEnc);
                } catch (InvalidKeyException | IllegalBlockSizeException | BadPaddingException e) {
                    e.printStackTrace();
                }
            }
            ByteArrayOutputStream b_out = new ByteArrayOutputStream();
            try {
                objectOutputStream = new ObjectOutputStream(b_out);
            } catch (IOException e) {
                System.out.println("Cannot create objectOutputStream");
                e.printStackTrace();
            }

            objectOutputStream.writeObject(txMessage);

            byte[] outBuf = b_out.toByteArray();

            DatagramPacket dgram = new DatagramPacket(outBuf, outBuf.length,InetAddress.getByName(groupAddress), port);
            listeningSocket.setTimeToLive(1);
            listeningSocket.send(dgram);

        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private void sendLeaveMsg() {
        Message message = new LeaveMessage();
        ObjectOutputStream objectOutputStream = null;

        //------------------------------------------------------
        //CONNECT TO THE SERVER AND SEND HIM THE LEAVE MESSAGE
        //------------------------------------------------------
        try {
            serverSocket = new Socket(serverAddress, SERVER_PORT);
            objectOutputStream = new ObjectOutputStream(serverSocket.getOutputStream());
        } catch (IOException e) {
            System.out.println("Cannot create objectOutputStream");
            e.printStackTrace();
        }

        try {
            objectOutputStream.writeObject(message);
            objectOutputStream.close();
            serverSocket.close();
            System.out.println("You left the group");
        } catch (IOException e) {
            System.out.println("Cannot write object to group master");
            e.printStackTrace();
        }

        monitoringThread.interrupt();
        joined = false;
    }


    class WriteChat implements Runnable{

        private GroupMember groupMember;

        public WriteChat(GroupMember groupMember){
            this.groupMember = groupMember;
        }

        @Override
        public void run() {
            //LISTEN FOR KEYBOARD INPUT
            String line="";
            System.out.println("Welcome! Type the message to broadcast to the multicast group. :join to join or :leave to leave)");
            while(true){

                BufferedReader br = new BufferedReader(new InputStreamReader(System.in));
                System.out.println("Type the message to broadcast (exit to leave)...");
                try {
                    line = br.readLine();
                } catch (IOException e) {
                    e.printStackTrace();
                }
                if(line.equals(":leave")){
                    groupMember.sendLeaveMsg();
                }
                else if(line.equals(":join")){
                    groupMember.join();
                }
                else{
                    groupMember.broadcastMessage(line);
                }
            }
        }
    }

    class GroupMemberChecker implements Runnable{
        MulticastSocket monitoringSocket;
        public GroupMemberChecker(){

            try {
                monitoringSocket = new MulticastSocket(MONITORING_PORT);
                InetAddress address = InetAddress.getByName(groupAddress);
                monitoringSocket.joinGroup(address);
            } catch (IOException e) {
                e.printStackTrace();
            }
        }

        @Override
        public void run() {
            while(!Thread.interrupted()){
                try {
                    byte[] b = new byte[65535];
                    ByteArrayInputStream bis = new ByteArrayInputStream(b);
                    DatagramPacket dgram = new DatagramPacket(b, b.length);
                    monitoringSocket.receive(dgram);
                    ObjectOutputStream objectOutputStream = null;
                    ObjectInputStream objectInputStream = new ObjectInputStream(bis);
                    Message inputMsg = (Message) objectInputStream.readObject();
                    Socket socket = null;
                    if(inputMsg instanceof AliveMessage){
                        try {
                            socket = new Socket(serverAddress, MONITORING_PORT);
                        } catch (IOException e) {
                            e.printStackTrace();
                        }

                        try {
                            objectOutputStream = new ObjectOutputStream(socket.getOutputStream());
                        } catch (IOException e) {
                            System.out.println("Cannot create objectOutputStream");
                            e.printStackTrace();
                        }

                        try {
                            objectOutputStream.writeObject(new AliveMessage());
                            //System.out.println("Message to stay in the group sent");
                        } catch (IOException e) {
                            System.out.println("Cannot write object to group master");
                            e.printStackTrace();
                        }
                    }
                }
                catch (IOException | ClassNotFoundException e){
                    e.printStackTrace();
                }
            }
        }
    }
}