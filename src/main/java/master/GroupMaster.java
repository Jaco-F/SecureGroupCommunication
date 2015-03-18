package master;

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
    public final static int MAX_MEMBERS_ALLOWED = 8;
    public final static String MCAST_ADDR = "239.0.0.1";
    public final static int DEST_PORT = 12345;

    protected HashMap<Integer,InetAddress> namingMap;
    protected boolean[] namingSlotStatus;

    protected TableManager tableManager;

    protected Cipher desCipher;
    protected Cipher rsaCipher;

    protected final Object lockJoin;

    public GroupMaster() {
        namingSlotStatus = new boolean[MAX_MEMBERS_ALLOWED];

        lockJoin = new Object();

        for (int i = 0; i < MAX_MEMBERS_ALLOWED; i++) {
            namingSlotStatus[i] = false;
        }
        tableManager = new TableManager();
        namingMap = new HashMap<Integer,InetAddress>();

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

        while(true) {
            Socket client = null;
            SocketAddress socketAddress = null;
            //WAIT MESSAGE
            try {
                client = serverSocket.accept();
                System.out.println("Client Request received");
            } catch (IOException e) {
                e.printStackTrace();
            }

            GroupMasterManageMessages groupMasterManageMessages = new GroupMasterManageMessages(client, this);
            Thread thread = new Thread(groupMasterManageMessages);
            thread.start();
        }

    }

}
