package master;

import utils.Converter;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.security.NoSuchAlgorithmException;

/**
 * Created by ame on 18/03/15.
 */
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

    public void recomputeKeks(int memberId) {
        System.out.println("Recomputing keks...");
        String binaryId = Converter.binaryConversion(memberId);
        for (int i = 0; i < 3; i++) {

            //SAVE OLD KEK TABLE
            oldKekTable[0][i] = kekTable[0][i];
            oldKekTable[1][i] = kekTable[1][i];

            int index = Character.getNumericValue(binaryId.charAt(i));
            kekTable[index][i] = keygen.generateKey();

            System.out.println("Changed kek " + index + i);

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