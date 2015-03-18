package master;

import utils.*;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.SecretKey;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.*;
import java.security.InvalidKeyException;
import java.security.PublicKey;

/**
 * Created by ame on 18/03/15.
 */
class GroupMasterManageMessages implements Runnable {
    private Socket memberSocket;
    private InetSocketAddress socketAddress;
    GroupMaster groupMaster;

    public GroupMasterManageMessages(Socket clientSocket, GroupMaster groupMaster) {
        memberSocket = clientSocket;
        socketAddress = (InetSocketAddress) clientSocket.getRemoteSocketAddress();
        this.groupMaster = groupMaster;
    }

    @Override
    public void run() {

        ObjectInputStream objectInputStream = null;
        Message messageIn = null;

        //GET THE OBJECT MESSAGE
        try {
            objectInputStream = new ObjectInputStream(memberSocket.getInputStream());
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


    private void handleJoin(JoinMessage message, InetAddress address) {
        int availableId = -1;
        if (groupMaster.namingMap.containsValue(address)) {
            System.out.println("Received a join message from a member already in the group");
            return;
        }

        while (groupMaster.namingMap.size() >= groupMaster.MAX_MEMBERS_ALLOWED) {
            try {
                System.out.println("In wait...");

                synchronized (groupMaster.lockJoin) {
                    groupMaster.lockJoin.wait();
                }

                System.out.println("Wait finished");
            } catch (InterruptedException e) {
                e.printStackTrace();
            }
        }

        if ((groupMaster.namingMap.size() < groupMaster.MAX_MEMBERS_ALLOWED) {
            System.out.println("Receiving join message .. ");
            //FIND AVAILABLE ID FOR THE MEMBER REQUESTING ACCESS

            for (int i = 0; i < groupMaster.MAX_MEMBERS_ALLOWED; i++) {
                if (!groupMaster.namingSlotStatus[i]) {
                    availableId = i;
                    break;
                }
            }

            if (availableId != -1) {
                groupMaster.namingSlotStatus[availableId] = true;
                (groupMaster.namingMap.put(availableId, address);

                groupMaster.tableManager.recomputeDek();
                groupMaster.tableManager.recomputeKeks(availableId);

                sendKeysJoin(message.getPublicKey(), availableId);
                System.out.println(address.getHostAddress() + " now is in the group!");
            }
        }
    }

    private void handleLeave(InetAddress address) {
        //CHECK IF THE CLIENT EXISTS
        Boolean memberPresent = false;
        for (int i = 0; i <= groupMaster.namingMap.size(); i++) {
            if (groupMaster.namingSlotStatus[i]) {
                InetAddress senderAddress = groupMaster.namingMap.get(i);
                if (senderAddress.equals(address)) {
                    memberPresent = true;
                }
            }
        }
        if (!memberPresent) {
            System.out.println("Received a leave message from a non group member");
            return;
        }

        int leaveMember = -1;

        for (int i = 0; i <= groupMaster.namingMap.size(); i++) {
            if (groupMaster.namingSlotStatus[i]) {
                if (groupMaster.namingMap.get(i).equals(address)) {
                    leaveMember = i;
                }
            }
        }
        if (leaveMember != -1) {
            groupMaster.namingMap.remove(leaveMember);
            groupMaster.namingSlotStatus[leaveMember] = false;
            groupMaster.tableManager.recomputeDek();
            groupMaster.tableManager.recomputeKeks(leaveMember);
            sendKeysLeave(leaveMember);

            System.out.println("Notifying all");
            synchronized (groupMaster.lockJoin) {
                groupMaster.lockJoin.notifyAll();
            }
            System.out.println("Notify done");
        }


    }

    //------------------------------------------------------------------
    //SEND THE NEW DEK AND KEKs TO THE NEW ENTRY ENCRYPTED WITH PK
    //SEND THE NEW DEK TO THE OLD MEMBERS ENCRYPTED WITH THE OLD DEK (?)(?)
    //------------------------------------------------------------------
    private void sendKeysJoin(PublicKey publicKey, int newEntryId) {
        byte[] encryptedKeys;
        SecretKey[][] kekTable = groupMaster.tableManager.getKekTable();

        ServerJoinKeys serverJoinKeys = new ServerJoinKeys();

        String binaryId = Converter.binaryConversion(newEntryId);

        //ENCRYPT DEK AND KEKs TO BE SENT TO THE NEW ENTRY WITH HIS PK
        try {
            groupMaster.rsaCipher.init(Cipher.ENCRYPT_MODE, publicKey);
        } catch (InvalidKeyException e) {
            System.out.println("Can't initialize public key cipher");
            e.printStackTrace();
        }

        try {
            encryptedKeys = groupMaster.rsaCipher.doFinal(groupMaster.tableManager.getDek().getEncoded());
            serverJoinKeys.setDek(encryptedKeys);

            int index = Character.getNumericValue(binaryId.charAt(0));
            encryptedKeys = groupMaster.rsaCipher.doFinal(kekTable[index][0].getEncoded());
            serverJoinKeys.setKek1(encryptedKeys);

            index = Character.getNumericValue(binaryId.charAt(1));
            encryptedKeys = groupMaster.rsaCipher.doFinal(kekTable[index][1].getEncoded());
            serverJoinKeys.setKek2(encryptedKeys);

            index = Character.getNumericValue(binaryId.charAt(2));
            encryptedKeys = groupMaster.rsaCipher.doFinal(kekTable[index][2].getEncoded());
            serverJoinKeys.setKek3(encryptedKeys);

        } catch (IllegalBlockSizeException | BadPaddingException e) {
            System.out.println("Error in building the keys package");
            e.printStackTrace();
        }

        //SEND THE MESSAGE TO THE NEW ENTRY
        try {
            DatagramSocket socket = new DatagramSocket();
            ByteArrayOutputStream b_out = new ByteArrayOutputStream();
            ObjectOutputStream o_out = new ObjectOutputStream(b_out);

            o_out.writeObject(serverJoinKeys);

            byte[] b = b_out.toByteArray();

            DatagramPacket dgram = new DatagramPacket(b, b.length, groupMaster.namingMap.get(newEntryId), groupMaster.DEST_PORT);
            socket.send(dgram);
            socket.close();

        } catch (IOException e) {
            System.out.println("Error in new dek message send to the new entry");
            e.printStackTrace();
        }

        serverJoinKeys = new ServerJoinKeys();

        SecretKey[][] oldKekTable = groupMaster.tableManager.getOldKekTable();

        try {
            //ENCRYPT NEW DEK WITH OLD DEK
            groupMaster.desCipher.init(Cipher.ENCRYPT_MODE, groupMaster.tableManager.getOldDek());
            serverJoinKeys.setDek(groupMaster.desCipher.doFinal(groupMaster.tableManager.getDek().getEncoded()));

            //ENCRYPT NEW KEK1 WITH OLD KEK1
            int index = Character.getNumericValue(binaryId.charAt(0));
            groupMaster.desCipher.init(Cipher.ENCRYPT_MODE, oldKekTable[index][0]);
            serverJoinKeys.setKek1(groupMaster.desCipher.doFinal(kekTable[index][0].getEncoded()));

            //ENCRYPT NEW KEK2 WITH OLD KEK2
            index = Character.getNumericValue(binaryId.charAt(1));
            groupMaster.desCipher.init(Cipher.ENCRYPT_MODE, oldKekTable[index][1]);
            serverJoinKeys.setKek2(groupMaster.desCipher.doFinal(kekTable[index][1].getEncoded()));

            //ENCRYPT NEW KEK3 WITH OLD KEK3
            index = Character.getNumericValue(binaryId.charAt(2));
            groupMaster.desCipher.init(Cipher.ENCRYPT_MODE, oldKekTable[index][2]);
            serverJoinKeys.setKek3(groupMaster.desCipher.doFinal(kekTable[index][2].getEncoded()));

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
        SecretKey[][] kekTable = groupMaster.tableManager.getKekTable();

        SecretKey dek = groupMaster.tableManager.getDek();

        String binaryId = Converter.binaryConversion(leaveId);

        ServerLeaveDek serverLeaveDek = new ServerLeaveDek();


        try {
            //ENCRYPT NEW DEK WITH KEK1
            int index = 1 - Character.getNumericValue(binaryId.charAt(0));
            groupMaster.desCipher.init(Cipher.ENCRYPT_MODE, kekTable[index][0]);
            serverLeaveDek.setDek(groupMaster.desCipher.doFinal(dek.getEncoded()));
            broadcastMessage(serverLeaveDek);

            //ENCRYPT NEW DEK WITH KEK1
            index = 1 - Character.getNumericValue(binaryId.charAt(1));
            groupMaster.desCipher.init(Cipher.ENCRYPT_MODE, kekTable[index][1]);
            serverLeaveDek.setDek(groupMaster.desCipher.doFinal(dek.getEncoded()));
            broadcastMessage(serverLeaveDek);

            //ENCRYPT NEW DEK WITH KEK1
            index = 1 - Character.getNumericValue(binaryId.charAt(2));
            groupMaster.desCipher.init(Cipher.ENCRYPT_MODE, kekTable[index][2]);
            serverLeaveDek.setDek(groupMaster.desCipher.doFinal(dek.getEncoded()));
            broadcastMessage(serverLeaveDek);

        } catch (InvalidKeyException | BadPaddingException | IllegalBlockSizeException e) {
            System.out.println("Error in encrypting the dek during leaving distribution dek process");
            //e.printStackTrace();
        }

        ServerLeaveKek serverLeaveKeys = new ServerLeaveKek();

        SecretKey[][] oldKekTable = groupMaster.tableManager.getOldKekTable();

        byte[] temp;

        try {

            //ENCRYPT NEW KEK1 WITH OLD KEK1 AND NEW DEK
            int index = 1 - Character.getNumericValue(binaryId.charAt(0));
            groupMaster.desCipher.init(Cipher.ENCRYPT_MODE, oldKekTable[index][0]);
            temp = groupMaster.desCipher.doFinal(kekTable[index][0].getEncoded());
            groupMaster.desCipher.init(Cipher.ENCRYPT_MODE, dek);
            serverLeaveKeys.setKek1(groupMaster.desCipher.doFinal(temp));

            //ENCRYPT NEW KEK2 WITH OLD KEK2 AND NEW DEK
            index = 1 - Character.getNumericValue(binaryId.charAt(1));
            groupMaster.desCipher.init(Cipher.ENCRYPT_MODE, oldKekTable[index][1]);
            temp = groupMaster.desCipher.doFinal(kekTable[index][1].getEncoded());
            groupMaster.desCipher.init(Cipher.ENCRYPT_MODE, dek);
            serverLeaveKeys.setKek2(groupMaster.desCipher.doFinal(temp));

            //ENCRYPT NEW KEK3 WITH OLD KEK3 AND NEW DEK
            index = 1 - Character.getNumericValue(binaryId.charAt(2));
            groupMaster.desCipher.init(Cipher.ENCRYPT_MODE, oldKekTable[index][2]);
            temp = groupMaster.desCipher.doFinal(kekTable[index][2].getEncoded());
            groupMaster.desCipher.init(Cipher.ENCRYPT_MODE, dek);
            serverLeaveKeys.setKek3(groupMaster.desCipher.doFinal(temp));

        } catch (InvalidKeyException | BadPaddingException | IllegalBlockSizeException e) {
            System.out.println("Error in encrypting the keks during leaving distribution keks process");
            //e.printStackTrace();
        }

        System.out.println("Sending new keks");
        broadcastMessage(serverLeaveKeys);
    }

    private void broadcastMessage(Message message) {
        MulticastSocket socket;

        try {
            socket = new MulticastSocket();

            ByteArrayOutputStream b_out = new ByteArrayOutputStream();
            ObjectOutputStream o_out = new ObjectOutputStream(b_out);

            o_out.writeObject(message);

            byte[] outBuf = b_out.toByteArray();

            DatagramPacket dgram = new DatagramPacket(outBuf, outBuf.length, InetAddress.getByName(groupMaster.MCAST_ADDR), groupMaster.DEST_PORT);
            socket.setTimeToLive(1);
            socket.send(dgram);
            socket.close();

        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}