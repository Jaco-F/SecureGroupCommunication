
import utils.*;

import javax.crypto.*;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.util.BitSet;
import java.util.HashMap;

/**
 * Created by Jacopo on 11/03/2015.
 */
public class GroupMaster implements Runnable{
    private final static int MAX_MEMBERS_ALLOWED = 8;

    private HashMap<Integer,Socket> namingMap;
    private boolean[] namingSlotStatus;

    private TableManager tableManager;

    private Cipher desCipher;
    private Cipher rsaCipher;

    private int serverPort = 4000;
    private ServerSocket serverSocket;

    public GroupMaster() {
        namingSlotStatus = new boolean[MAX_MEMBERS_ALLOWED];
        for (int i = 0; i < MAX_MEMBERS_ALLOWED; i++) {
            namingSlotStatus[i] = false;
        }
        tableManager = new TableManager();
        namingMap = new HashMap<Integer,Socket>();

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
        Socket client = null;
        ObjectInputStream objectInputStream = null;
        Message messageIn = null;

        //CREATE SERVER SOCKET
        try {
            serverSocket = new ServerSocket(serverPort);
        } catch (IOException e) {
            System.out.println("Error in Server creation");
            e.printStackTrace();
        }

        while(true){

            //WAIT MESSAGE
            try {
                client = serverSocket.accept();
            } catch (IOException e) {
                e.printStackTrace();
            }

            //GET THE OBJECT MESSAGE
            try {
                objectInputStream = new ObjectInputStream(client.getInputStream());
            } catch (IOException e) {
                e.printStackTrace();
            }
            try {
                messageIn = (Message)objectInputStream.readObject();
            } catch (IOException | ClassNotFoundException e) {
                e.printStackTrace();
            }

            if(messageIn.getClass().getName() == "JoinMessage"){
                handleJoin((JoinMessage)messageIn);
            }
            else if (messageIn.getClass().getName() == "LeaveMessage"){
                handleLeave((LeaveMessage)messageIn);
            }


        }

    }


    private void handleJoin(JoinMessage message) {

        int availableId = -1;
        //TODO: aggiungere wait in caso > MAX
        if (namingMap.size() < MAX_MEMBERS_ALLOWED) {
            //FIND AVAILABLE ID FOR THE MEMBER REQUESTING ACCESS
            for (int i = 0; i< MAX_MEMBERS_ALLOWED;i++){
                if (!namingSlotStatus[i]) {
                    availableId = i;
                    break;
                }
            }

            if (availableId != -1) {
                namingSlotStatus[availableId] = true;
                namingMap.put(availableId,message.getSource());
                tableManager.recomputeDek();
                tableManager.recomputeKeks(availableId);

                sendKeysJoin(message.getPublicKey(),availableId);
            }

        }
    }

    private void handleLeave(LeaveMessage message) {
        //CHECK IF THE CLIENT EXISTS
        if(!namingMap.containsValue(message.getSource())){
            System.out.println("This client is not in the group");
            return;
        }

        int leaveMember = -1;

        for (int i = 0; i< MAX_MEMBERS_ALLOWED;i++){
            if (namingSlotStatus[i]) {
                if (namingMap.get(i) == message.getSource()){
                    leaveMember = i;
                }
            }
        }
        if(leaveMember != -1){
            namingMap.remove(leaveMember);
            namingSlotStatus[leaveMember] = false;
            tableManager.recomputeDek();
            tableManager.recomputeKeks(leaveMember);
            sendKeysLeave(leaveMember);
        }


    }

    //------------------------------------------------------------------
    //SEND THE NEW DEK AND KEKs TO THE NEW ENTRY ENCRYPTED WITH PK
    //SEND THE NEW DEK TO THE OLD MEMBERS ENCRYPTED WITH THE OLD DEK (?)(?)
    //------------------------------------------------------------------
    private void sendKeysJoin(PublicKey publicKey,int newEntryId){
        byte[] encryptedKeys;
        SecretKey[][] kekTable = tableManager.getKekTable();

        ServerInitMessage serverInitMessage = new ServerInitMessage();

        String binaryId = Integer.toBinaryString(newEntryId);

        //ENCRYPT DEK AND KEKs TO BE SENT TO THE NEW ENTRY WITH HIS PK
        try {
            rsaCipher.init(Cipher.ENCRYPT_MODE,publicKey);
        } catch (InvalidKeyException e) {
            System.out.println("Can't initialize public key cipher");
            e.printStackTrace();
        }

        try {
            encryptedKeys = rsaCipher.doFinal(tableManager.getDek().getEncoded());
            serverInitMessage.setDek(encryptedKeys);

            int index = Character.getNumericValue(binaryId.charAt(0));
            encryptedKeys = rsaCipher.doFinal(kekTable[index][0].getEncoded());
            serverInitMessage.setKek1(encryptedKeys);

            index = Character.getNumericValue(binaryId.charAt(1));
            encryptedKeys = rsaCipher.doFinal(kekTable[index][1].getEncoded());
            serverInitMessage.setKek2(encryptedKeys);

            index = Character.getNumericValue(binaryId.charAt(2));
            encryptedKeys = rsaCipher.doFinal(kekTable[index][2].getEncoded());
            serverInitMessage.setKek3(encryptedKeys);

        } catch (IllegalBlockSizeException | BadPaddingException e) {
            System.out.println("Error in building the keys package");
            e.printStackTrace();
        }

        //SEND THE MESSAGE TO THE NEW ENTRY
        try {
            Socket socket = namingMap.get(newEntryId);
            ObjectOutputStream objectOutputStream = new ObjectOutputStream(socket.getOutputStream());
            objectOutputStream.writeObject(serverInitMessage);
            socket.close();

        } catch (IOException e) {
            System.out.println("Error in new dek message send to the new entry");
            e.printStackTrace();
        }

        //SEND NEW KEKS AND DEK TO OTHERS
        for (int i = 0; i< MAX_MEMBERS_ALLOWED;i++){
            if ((namingSlotStatus[i])&&(i!=newEntryId)) {
                sendKeys(i);
            }
        }


    }

    //------------------------------------------------------------------
    //SEND THE NEW DEK AND KEKs TO THE OTHER MEMBERS
    //SEND THE NEW DEK TO THE OLD MEMBERS ENCRYPTED WITH THE KEK THAT THE LEAVE MEMBER NOT KNOW
    //------------------------------------------------------------------
    public void sendKeysLeave(int leaveId){
        SecretKey[][] kekTable = tableManager.getKekTable();

        SecretKey dek = tableManager.getDek();

        String binaryId = Integer.toBinaryString(leaveId);

        ServerLeaveDek serverLeaveDek = new ServerLeaveDek();


        try {
            //ENCRYPT NEW DEK WITH KEK1
            int index = 1 - Character.getNumericValue(binaryId.charAt(0));
            desCipher.init(Cipher.ENCRYPT_MODE, kekTable[index][0]);
            serverLeaveDek.setDek(desCipher.doFinal(dek.getEncoded()));
            broadcast(serverLeaveDek);

            //ENCRYPT NEW DEK WITH KEK1
            index = 1 - Character.getNumericValue(binaryId.charAt(1));
            desCipher.init(Cipher.ENCRYPT_MODE, kekTable[index][1]);
            serverLeaveDek.setDek(desCipher.doFinal(dek.getEncoded()));
            broadcast(serverLeaveDek);

            //ENCRYPT NEW DEK WITH KEK1
            index = 1 - Character.getNumericValue(binaryId.charAt(2));
            desCipher.init(Cipher.ENCRYPT_MODE, kekTable[index][2]);
            serverLeaveDek.setDek(desCipher.doFinal(dek.getEncoded()));
            broadcast(serverLeaveDek);

            //SEND NEW KEKS
            for (int i = 0; i< MAX_MEMBERS_ALLOWED;i++){
                if (namingSlotStatus[i]) {
                    sendKekLeave(i);
                }
            }

        } catch (InvalidKeyException | BadPaddingException | IllegalBlockSizeException e) {
            e.printStackTrace();
        }


    }

    public void sendKekLeave(int member){
        ServerLeaveKek serverLeaveKek = new ServerLeaveKek();

        String binaryId = Integer.toBinaryString(member);

        SecretKey[][] oldKekTable = tableManager.getOldKekTable();
        SecretKey[][] kekTable = tableManager.getKekTable();
        SecretKey dek = tableManager.getDek();

        byte [] temp;

        try {

            //ENCRYPT NEW KEK1 WITH OLD KEK1 AND NEW DEK
            int index = Character.getNumericValue(binaryId.charAt(0));
            desCipher.init(Cipher.ENCRYPT_MODE, oldKekTable[index][0]);
            temp = desCipher.doFinal(kekTable[index][0].getEncoded());
            desCipher.init(Cipher.ENCRYPT_MODE, dek);
            serverLeaveKek.setKek1(desCipher.doFinal(temp));

            //ENCRYPT NEW KEK2 WITH OLD KEK2 AND NEW DEK
            index = Character.getNumericValue(binaryId.charAt(1));
            desCipher.init(Cipher.ENCRYPT_MODE, oldKekTable[index][1]);
            temp = desCipher.doFinal(kekTable[index][1].getEncoded());
            desCipher.init(Cipher.ENCRYPT_MODE, dek);
            serverLeaveKek.setKek1(desCipher.doFinal(temp));

            //ENCRYPT NEW KEK3 WITH OLD KEK3 AND NEW DEK
            index = Character.getNumericValue(binaryId.charAt(2));
            desCipher.init(Cipher.ENCRYPT_MODE, oldKekTable[index][2]);
            temp = desCipher.doFinal(kekTable[index][2].getEncoded());
            desCipher.init(Cipher.ENCRYPT_MODE, dek);
            serverLeaveKek.setKek1(desCipher.doFinal(temp));

        } catch (InvalidKeyException | BadPaddingException | IllegalBlockSizeException e) {
            System.out.println("Error in building the keys package");
            e.printStackTrace();
        }

        //SEND THE MESSAGE WITH THE NEW KEK AND DEK
        try {
            Socket socket = namingMap.get(member);
            ObjectOutputStream objectOutputStream = new ObjectOutputStream(socket.getOutputStream());
            objectOutputStream.writeObject(serverLeaveKek);
            socket.close();

        } catch (IOException e) {
            System.out.println("Error in new dek-kek message send to "+ member);
            e.printStackTrace();
        }


    }

    public void sendKeys(int member){
        ServerInitMessage serverInitMessage = new ServerInitMessage();

        String binaryId = Integer.toBinaryString(member);

        SecretKey[][] oldKekTable = tableManager.getOldKekTable();
        SecretKey[][] kekTable = tableManager.getKekTable();

        try {
            //ENCRYPT NEW DEK WITH OLD DEK
            desCipher.init(Cipher.ENCRYPT_MODE, tableManager.getOldDek());
            serverInitMessage.setDek(desCipher.doFinal(tableManager.getDek().getEncoded()));

            //ENCRYPT NEW KEK1 WITH OLD KEK1
            int index = Character.getNumericValue(binaryId.charAt(0));
            desCipher.init(Cipher.ENCRYPT_MODE, oldKekTable[index][0]);
            serverInitMessage.setKek1(desCipher.doFinal(kekTable[index][0].getEncoded()));

            //ENCRYPT NEW KEK2 WITH OLD KEK2
            index = Character.getNumericValue(binaryId.charAt(1));
            desCipher.init(Cipher.ENCRYPT_MODE, oldKekTable[index][1]);
            serverInitMessage.setKek2(desCipher.doFinal(kekTable[index][1].getEncoded()));

            //ENCRYPT NEW KEK3 WITH OLD KEK3
            index = Character.getNumericValue(binaryId.charAt(2));
            desCipher.init(Cipher.ENCRYPT_MODE, oldKekTable[index][2]);
            serverInitMessage.setKek3(desCipher.doFinal(kekTable[index][2].getEncoded()));

        } catch (InvalidKeyException | BadPaddingException | IllegalBlockSizeException e) {
            System.out.println("Error in building the keys package");
            e.printStackTrace();
        }

        //SEND THE MESSAGE WITH THE NEW KEK AND DEK
        try {
            Socket socket = namingMap.get(member);
            ObjectOutputStream objectOutputStream = new ObjectOutputStream(socket.getOutputStream());
            objectOutputStream.writeObject(serverInitMessage);
            socket.close();

        } catch (IOException e) {
            System.out.println("Error in new dek-kek message send to "+ member);
            e.printStackTrace();
        }

    }

    public void broadcast(ServerLeaveDek serverLeaveDek){
        for (int i = 0; i< MAX_MEMBERS_ALLOWED;i++){
            if (namingSlotStatus[i]) {
                try {
                    Socket socket = namingMap.get(i);
                    ObjectOutputStream objectOutputStream = new ObjectOutputStream(socket.getOutputStream());
                    objectOutputStream.writeObject(serverLeaveDek);
                    socket.close();
                } catch (IOException e) {
                    System.out.println("Error in new dek message send to "+ i);
                    e.printStackTrace();
                }
            }
        }
    }

}

class TableManager{
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

        try {
            keygen = KeyGenerator.getInstance("DES");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }

        dek = keygen.generateKey();
        oldDek = null;

        for(int i = 0;i < 2;i++) {
            for(int j = 0; j < 3; j++) {
                kekTable[i][j] = keygen.generateKey();
            }
        }
    }

    public void recomputeDek(){
        try {
            keygen = KeyGenerator.getInstance("DES");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        oldDek = dek;
        dek = keygen.generateKey();

    }

    public void recomputeKeks(int memberId){
        String binaryId = Integer.toBinaryString(memberId);
        for (int i = 0; i < 3; i++){

            //SAVE OLD KEK TABLE
            oldKekTable[0][i] = kekTable[0][i];
            oldKekTable[1][i] = kekTable[1][i];

            int index = Character.getNumericValue(binaryId.charAt(i));
            kekTable[index][i] = keygen.generateKey();

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

    public SecretKey[][] getOldKekTable() { return oldKekTable; }
}
