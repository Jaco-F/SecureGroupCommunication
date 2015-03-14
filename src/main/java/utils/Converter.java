package utils;

/**
 * Created by Jacopo on 14/03/2015.
 */
public class Converter {
    public static String binaryConversion(int num){
        String binaryNum = Integer.toBinaryString(num);
        if (binaryNum.length()==1) {
            return "00" + binaryNum;
        }
        else if (binaryNum.length() == 2) {
            return "0" + binaryNum;
        }
        else {
            return binaryNum;
        }
    }
}
