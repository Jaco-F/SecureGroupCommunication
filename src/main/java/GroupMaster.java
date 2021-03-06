
import utils.*;

import javax.crypto.*;
import java.io.*;
import java.net.*;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;

/**
 * Created by Jacopo on 11/03/2015.
 */

public class GroupMaster implements Runnable {
    private final int MAX_MEMBERS_ALLOWED = 8;
    private final String MCAST_ADDR = "239.0.0.1";
    private final int DEST_PORT = 12345;
    private final int JOIN_PORT = 14000;

    private HashMap<Integer, InetAddress> namingMap;
    private boolean[] namingSlotStatus;

    private TableManager tableManager;

    private Cipher desCipher;
    private Cipher rsaCipher;

    public GroupMaster() {
        namingSlotStatus = new boolean[MAX_MEMBERS_ALLOWED];

        for (int i = 0; i < MAX_MEMBERS_ALLOWED; i++) {
            namingSlotStatus[i] = false;
        }
        tableManager = new TableManager();
        namingMap = new HashMap<Integer, InetAddress>();

        try {
            //init DES cipher
            desCipher = Cipher.getInstance("DES");
        } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
            e.printStackTrace();
        }

        try {
            //init RSA cipher
            rsaCipher = Cipher.getInstance("RSA");
        } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
            e.printStackTrace();
        }
    }

    @Override
    public void run() {
        final int serverPort = 13000;
        ServerSocket serverSocket = null;

        System.out.println("Server is starting on port : " + serverPort);
        //CREATE SERVER SOCKET
        try {
            serverSocket = new ServerSocket(serverPort);
        } catch (IOException e) {
            System.out.println("Error in Server creation");
            //e.printStackTrace();
        }
        System.out.println("Server started on port : " + serverPort);

        //init monitoring tool
        GroupMasterChecker groupMasterChecker = new GroupMasterChecker();
        Thread checkerThread = new Thread(groupMasterChecker);
        checkerThread.start();

        while (true) {
            Socket client = null;
            SocketAddress socketAddress = null;
            //WAIT MESSAGE
            try {
                client = serverSocket.accept();
                System.out.println("Client Request received");
            } catch (IOException e) {
                e.printStackTrace();
            }

            //allocate new message manager
            GroupMasterManageMessages groupMasterManageMessages = new GroupMasterManageMessages(client);
            Thread thread = new Thread(groupMasterManageMessages);
            thread.start();
        }
    }

    //
    private synchronized void handleJoin(JoinMessage message, InetAddress address) {
        int availableId = -1;
        if (namingMap.containsValue(address)) {
            return;
        }


        while (namingMap.size() >= MAX_MEMBERS_ALLOWED) {
            try {
                System.out.println("In wait...");
                this.wait();
                System.out.println("Wait finished");
            } catch (InterruptedException e) {
                e.printStackTrace();
            }
        }

        if (namingMap.size() < MAX_MEMBERS_ALLOWED) {
            System.out.println("Receiving join message .. ");

            //FIND AVAILABLE ID FOR THE MEMBER REQUESTING ACCESS
            for (int i = 0; i < MAX_MEMBERS_ALLOWED; i++) {
                if (!namingSlotStatus[i]) {
                    availableId = i;
                    break;
                }
            }

            if (availableId != -1) {
                namingSlotStatus[availableId] = true;
                namingMap.put(availableId, address);

                tableManager.recomputeDek();
                tableManager.recomputeKeks(availableId);

                sendKeysJoin(message.getPublicKey(), availableId);
                System.out.println(address.getHostAddress() + " now is in the group!");
            }
        }
    }

    private synchronized void handleLeave(InetAddress address) {

        //CHECK IF THE CLIENT EXISTS
        int leaveMember = -1;
        for (int i = 0; i < MAX_MEMBERS_ALLOWED; i++) {
            if (namingSlotStatus[i]) {
                if (namingMap.get(i).equals(address)) {
                    leaveMember = i;
                    break;
                }
            }
        }
        if (leaveMember == -1) {
            //Ignore the request
            System.out.println("Received a leave message from a non group member");
            return;
        }

        namingMap.remove(leaveMember);
        namingSlotStatus[leaveMember] = false;

        //recompute DEK and KEKs based on the id of the member
        tableManager.recomputeDek();
        tableManager.recomputeKeks(leaveMember);
        sendKeysLeave(leaveMember);

        System.out.println("Notifying all");
        this.notify();
        System.out.println("Notify done");

    }

    //------------------------------------------------------------------
    //SEND THE NEW DEK AND KEKs TO THE NEW ENTRY ENCRYPTED WITH PK
    //SEND THE NEW DEK TO THE OLD MEMBERS ENCRYPTED WITH THE OLD DEK
    //SEND THE NEW KEKs TO THE OLD MEMBERS ENCRYPTED WITH THE OLD KEKs
    //------------------------------------------------------------------
    private void sendKeysJoin(PublicKey publicKey, int newEntryId) {
        byte[] encryptedKeys;
        SecretKey[][] kekTable = tableManager.getKekTable();

        ServerJoinKeys serverJoinKeys = new ServerJoinKeys();

        String binaryId = Converter.binaryConversion(newEntryId);

        //ENCRYPT DEK AND KEKs TO BE SENT TO THE NEW ENTRY WITH HIS PK
        try {
            rsaCipher.init(Cipher.ENCRYPT_MODE, publicKey);
        } catch (InvalidKeyException e) {
            System.out.println("Can't initialize public key cipher");
            e.printStackTrace();
        }

        try {
            encryptedKeys = rsaCipher.doFinal(tableManager.getDek().getEncoded());
            serverJoinKeys.setDek(encryptedKeys);

            int index = Character.getNumericValue(binaryId.charAt(0));
            encryptedKeys = rsaCipher.doFinal(kekTable[index][0].getEncoded());
            serverJoinKeys.setKek1(encryptedKeys);

            index = Character.getNumericValue(binaryId.charAt(1));
            encryptedKeys = rsaCipher.doFinal(kekTable[index][1].getEncoded());
            serverJoinKeys.setKek2(encryptedKeys);

            index = Character.getNumericValue(binaryId.charAt(2));
            encryptedKeys = rsaCipher.doFinal(kekTable[index][2].getEncoded());
            serverJoinKeys.setKek3(encryptedKeys);

        } catch (IllegalBlockSizeException | BadPaddingException e) {
            System.out.println("Error in building the keys package");
            e.printStackTrace();
        }

        //SEND THE MESSAGE TO THE NEW ENTRY
        Socket socket = null;
        ObjectOutputStream objectOutputStream = null;
        try {
            socket = new Socket(namingMap.get(newEntryId), JOIN_PORT);
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
            objectOutputStream.writeObject(serverJoinKeys);
            System.out.println("Message to join the group sent");
        } catch (IOException e) {
            System.out.println("Cannot write object to group master");
            e.printStackTrace();
        }

        serverJoinKeys = new ServerJoinKeys();

        SecretKey[][] oldKekTable = tableManager.getOldKekTable();

        try {
            //ENCRYPT NEW DEK WITH OLD DEK
            desCipher.init(Cipher.ENCRYPT_MODE, tableManager.getOldDek());
            serverJoinKeys.setDek(desCipher.doFinal(tableManager.getDek().getEncoded()));

            //ENCRYPT NEW KEK1 WITH OLD KEK1
            int index = Character.getNumericValue(binaryId.charAt(0));
            desCipher.init(Cipher.ENCRYPT_MODE, oldKekTable[index][0]);
            serverJoinKeys.setKek1(desCipher.doFinal(kekTable[index][0].getEncoded()));

            //ENCRYPT NEW KEK2 WITH OLD KEK2
            index = Character.getNumericValue(binaryId.charAt(1));
            desCipher.init(Cipher.ENCRYPT_MODE, oldKekTable[index][1]);
            serverJoinKeys.setKek2(desCipher.doFinal(kekTable[index][1].getEncoded()));

            //ENCRYPT NEW KEK3 WITH OLD KEK3
            index = Character.getNumericValue(binaryId.charAt(2));
            desCipher.init(Cipher.ENCRYPT_MODE, oldKekTable[index][2]);
            serverJoinKeys.setKek3(desCipher.doFinal(kekTable[index][2].getEncoded()));

        } catch (InvalidKeyException | BadPaddingException | IllegalBlockSizeException e) {
            System.out.println("Error in building the keys package");
            e.printStackTrace();
        }

        //broadcastJoin(serverJoinKeys, newEntryId);
        broadcastMessage(serverJoinKeys);

    }

    //------------------------------------------------------------------
    //SEND THE NEW DEK AND KEKs TO THE OTHER MEMBERS
    //SEND THE NEW DEK TO THE OLD MEMBERS ENCRYPTED WITH THE KEK THAT THE LEAVE MEMBER NOT KNOW
    //------------------------------------------------------------------
    private void sendKeysLeave(int leaveId) {
        SecretKey[][] kekTable = tableManager.getKekTable();

        SecretKey dek = tableManager.getDek();

        String binaryId = Converter.binaryConversion(leaveId);

        ServerLeaveDek serverLeaveDek = new ServerLeaveDek();


        try {
            //ENCRYPT NEW DEK WITH KEK1
            int index = 1 - Character.getNumericValue(binaryId.charAt(0));
            desCipher.init(Cipher.ENCRYPT_MODE, kekTable[index][0]);
            serverLeaveDek.setDek(desCipher.doFinal(dek.getEncoded()));
            broadcastMessage(serverLeaveDek);

            //ENCRYPT NEW DEK WITH KEK2
            index = 1 - Character.getNumericValue(binaryId.charAt(1));
            desCipher.init(Cipher.ENCRYPT_MODE, kekTable[index][1]);
            serverLeaveDek.setDek(desCipher.doFinal(dek.getEncoded()));
            broadcastMessage(serverLeaveDek);

            //ENCRYPT NEW DEK WITH KEK3
            index = 1 - Character.getNumericValue(binaryId.charAt(2));
            desCipher.init(Cipher.ENCRYPT_MODE, kekTable[index][2]);
            serverLeaveDek.setDek(desCipher.doFinal(dek.getEncoded()));
            broadcastMessage(serverLeaveDek);

        } catch (InvalidKeyException | BadPaddingException | IllegalBlockSizeException e) {
            System.out.println("Error in encrypting the dek during leaving distribution dek process");
            //e.printStackTrace();
        }

        ServerLeaveKek serverLeaveKeys = new ServerLeaveKek();

        SecretKey[][] oldKekTable = tableManager.getOldKekTable();

        byte[] temp;

        try {

            //ENCRYPT NEW KEK1 WITH OLD KEK1 AND NEW DEK
            int index = Character.getNumericValue(binaryId.charAt(0));
            desCipher.init(Cipher.ENCRYPT_MODE, dek);
            temp = desCipher.doFinal(kekTable[index][0].getEncoded());
            desCipher.init(Cipher.ENCRYPT_MODE, oldKekTable[index][0]);
            serverLeaveKeys.setKek1(desCipher.doFinal(temp));

            //ENCRYPT NEW KEK2 WITH OLD KEK2 AND NEW DEK
            index = Character.getNumericValue(binaryId.charAt(1));
            desCipher.init(Cipher.ENCRYPT_MODE, dek);
            temp = desCipher.doFinal(kekTable[index][1].getEncoded());
            desCipher.init(Cipher.ENCRYPT_MODE, oldKekTable[index][1]);
            serverLeaveKeys.setKek2(desCipher.doFinal(temp));

            //ENCRYPT NEW KEK3 WITH OLD KEK3 AND NEW DEK
            index = Character.getNumericValue(binaryId.charAt(2));
            desCipher.init(Cipher.ENCRYPT_MODE, dek);
            temp = desCipher.doFinal(kekTable[index][2].getEncoded());
            desCipher.init(Cipher.ENCRYPT_MODE, oldKekTable[index][2]);
            serverLeaveKeys.setKek3(desCipher.doFinal(temp));

        } catch (InvalidKeyException | BadPaddingException | IllegalBlockSizeException e) {
            System.out.println("Error in encrypting the keks during leaving distribution keks process");
            //e.printStackTrace();
        }
        try {
            Thread.sleep(2000);
        } catch (InterruptedException e) {
            e.printStackTrace();
        }
        System.out.println("Sending new keks");
        broadcastMessage(serverLeaveKeys);
    }

    //SEND MULTICAST MESSAGE TO ALL THE MULTICAST MEMBERS
    private void broadcastMessage(Message message) {
        MulticastSocket socket;

        try {
            socket = new MulticastSocket();

            ByteArrayOutputStream b_out = new ByteArrayOutputStream();
            ObjectOutputStream o_out = new ObjectOutputStream(b_out);

            o_out.writeObject(message);

            byte[] outBuf = b_out.toByteArray();

            DatagramPacket dgram = new DatagramPacket(outBuf, outBuf.length, InetAddress.getByName(MCAST_ADDR), DEST_PORT);
            socket.setTimeToLive(1);
            socket.send(dgram);
            socket.close();

        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    //A SINGLE MESSAGE HANDLER
    class GroupMasterManageMessages implements Runnable {
        private Socket memberSocket;
        private InetSocketAddress socketAddress;

        public GroupMasterManageMessages(Socket clientSocket) {
            memberSocket = clientSocket;
            socketAddress = (InetSocketAddress) clientSocket.getRemoteSocketAddress();
        }

        @Override
        public void run() {
            Socket client = memberSocket;

            ObjectInputStream objectInputStream = null;
            Message messageIn = null;

            //GET THE OBJECT MESSAGE
            try {
                objectInputStream = new ObjectInputStream(client.getInputStream());
            } catch (IOException e) {
                e.printStackTrace();
            }
            try {
                messageIn = (Message) objectInputStream.readObject();
            } catch (IOException | ClassNotFoundException e) {
                e.printStackTrace();
            }

            if (messageIn instanceof JoinMessage) {
                System.out.println("Join Message received");
                handleJoin((JoinMessage) messageIn, socketAddress.getAddress());
            } else if (messageIn instanceof LeaveMessage) {
                System.out.println("Leave Message received");
                handleLeave(socketAddress.getAddress());
            }
        }



    }

    //Monitoring module
    class GroupMasterChecker implements Runnable {
        private final int MONITORING_PORT = 15000;
        ServerSocket monitoringSocket;
        MulticastSocket socket;

        public GroupMasterChecker() {

            try {
                monitoringSocket = new ServerSocket(MONITORING_PORT);
            } catch (IOException e) {
                e.printStackTrace();
            }
        }

        @Override
        public void run() {
            List<InetAddress> members;
            while (true) {
                members = new ArrayList<InetAddress>(namingMap.values());

                try {
                    socket = new MulticastSocket();

                    ByteArrayOutputStream b_out = new ByteArrayOutputStream();
                    ObjectOutputStream o_out = new ObjectOutputStream(b_out);

                    o_out.writeObject(new AliveMessage());

                    byte[] outBuf = b_out.toByteArray();

                    DatagramPacket dgram = new DatagramPacket(outBuf, outBuf.length, InetAddress.getByName(MCAST_ADDR), MONITORING_PORT);
                    socket.setTimeToLive(1);
                    socket.send(dgram);
                    socket.close();


                    monitoringSocket.setSoTimeout(2000);

                    //accept all the message received in the timeout.
                    while (true) {
                        Socket client = null;
                        //WAIT MESSAGE
                        try {
                            client = monitoringSocket.accept();
                            members.remove(((InetSocketAddress) client.getRemoteSocketAddress()).getAddress());
                        }  catch (IOException e) {
                            socket.close();
                            break;
                        }
                    }

                    //manage with leave with all the other
                    for (InetAddress a : members) {
                        handleLeave(a);
                        System.out.println(a.toString() + " kicked out!");
                        Thread.sleep(5000);
                    }


                } catch (IOException | InterruptedException e) {
                    e.printStackTrace();
                }

                try {
                    Thread.sleep(5000);
                } catch (InterruptedException e) {
                    e.printStackTrace();
                }
            }
        }
    }

    //class that manage all the keys (KEKs and DEK)
    class TableManager {
        private SecretKey dek;
        private SecretKey oldDek;
        private SecretKey[][] kekTable;
        private SecretKey[][] oldKekTable;
        private KeyGenerator keygen;

        public TableManager() {
            kekTable = new SecretKey[2][3];
            oldKekTable = new SecretKey[2][3];
            try {
                keygen = KeyGenerator.getInstance("DES");
            } catch (NoSuchAlgorithmException e) {
                e.printStackTrace();
            }

            dek = keygen.generateKey();
            oldDek = null;

            for (int i = 0; i < 2; i++) {
                for (int j = 0; j < 3; j++) {
                    kekTable[i][j] = keygen.generateKey();
                }
            }
        }

        public void recomputeDek() {
            System.out.println("Recomputing Dek");
            oldDek = dek;
            dek = keygen.generateKey();

        }

        //recompute all keks considering the memberId
        public void recomputeKeks(int memberId) {
            System.out.println("Recomputing keks...");
            String binaryId = Converter.binaryConversion(memberId);
            for (int i = 0; i < 3; i++) {

                //SAVE OLD KEK TABLE
                oldKekTable[0][i] = kekTable[0][i];
                oldKekTable[1][i] = kekTable[1][i];

                int index = Character.getNumericValue(binaryId.charAt(i));
                kekTable[index][i] = keygen.generateKey();

                System.out.println("Changed kek "+index+i);

            }
        }

        public SecretKey[][] getKekTable() {
            return kekTable;
        }

        public SecretKey getDek() {
            return dek;
        }

        public SecretKey getOldDek() {
            return oldDek;
        }

        public SecretKey[][] getOldKekTable() {
            return oldKekTable;
        }
    }
}
