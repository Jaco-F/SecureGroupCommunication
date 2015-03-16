/**
 * Created by andre on 12/03/15.
 */
public class StartClient {
    public static void main(String[] args) throws InterruptedException {

        Thread memberThread = new Thread(new GroupMember("192.168.0.3",12000));
        memberThread.start();
        memberThread.join();
    }
}
