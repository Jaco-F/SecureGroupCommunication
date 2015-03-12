
/**
 * Created by andre on 12/03/15.
 */
public class StartClient2 {
    public static void main(String[] args) throws InterruptedException {

        Thread memberThread = new Thread(new GroupMember("localhost",15000));
        memberThread.start();
        memberThread.join();
    }
}
