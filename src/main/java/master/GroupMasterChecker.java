package master;

import utils.AliveMessage;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectOutputStream;
import java.net.*;
import java.util.ArrayList;
import java.util.List;

/**
 * Created by ame on 18/03/15.
 */
class GroupMasterChecker implements Runnable {
    private final int MONITORING_PORT = 15000;
    ServerSocket monitoringSocket;
    MulticastSocket socket;
    GroupMaster groupMaster;

    public GroupMasterChecker(GroupMaster groupMaster) {
        this.groupMaster = groupMaster;
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

                while (true) {
                    Socket client = null;
                    //WAIT MESSAGE
                    try {
                        System.out.println("Waiting alive...");
                        client = monitoringSocket.accept();
                        members.remove(((InetSocketAddress) client.getRemoteSocketAddress()).getAddress());
                    } catch (SocketException e) {
                        System.out.println("Timer Expired");
                        socket.close();
                        break;
                    } catch (IOException e) {
                        e.printStackTrace();
                    }
                }

                for (InetAddress a : members) {
                    handleLeave(a);
                }


            } catch (IOException e) {
                e.printStackTrace();
            }

            try {
                Thread.sleep(2000);
            } catch (InterruptedException e) {
                e.printStackTrace();
            }
        }
    }
}