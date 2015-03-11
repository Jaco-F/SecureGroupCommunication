import utils.JoinMessage;
import utils.Message;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import java.net.Socket;
import java.security.NoSuchAlgorithmException;
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

    }


    private void handleJoin(JoinMessage message) {
        int availableId = -1;
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
            }

        }
    }

    private void handleLeave() {

    }


}

class TableManager{
    private SecretKey dek;
    private SecretKey[][] kekTable;
    private KeyGenerator keygen;

    public TableManager() {
        kekTable = new SecretKey[2][3];
        try {
            keygen = KeyGenerator.getInstance("DES");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }

        dek = recomputeDek();

        for(int i = 0;i < 2;i++) {
            for(int j = 0; j < 3; j++) {
                kekTable[i][j] = keygen.generateKey();
            }
        }

    }

    public SecretKey recomputeDek(){
        try {
            keygen = KeyGenerator.getInstance("DES");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return keygen.generateKey();

    }

    public void recomputeKeks(int memberId){
        String binaryId = Integer.toBinaryString(memberId);
        for (int i = 0; i < 3; i++){
            int index = Character.getNumericValue(binaryId.charAt(i));
            kekTable[index][i] = keygen.generateKey();

        }
    }

    public SecretKey[][] getKekTable() {
        return kekTable;
    }
}
