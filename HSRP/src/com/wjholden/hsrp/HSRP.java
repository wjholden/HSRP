package com.wjholden.hsrp;

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.InetAddress;
import java.net.MulticastSocket;
import java.net.UnknownHostException;
import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.Map;
import java.util.TreeMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

/**
 * See <a href="https://tools.ietf.org/html/rfc2281">RFC 2281</a>.
 *
 * @author William John Holden (wjholden@gmail.com)
 */
public class HSRP {
    
    static final Map<Integer, String> stateName, opcodeName;
    static {
        stateName = new TreeMap<>();
        opcodeName = new TreeMap<>();
        
        opcodeName.put(0, "Hello");
        opcodeName.put(1, "Coup");
        opcodeName.put(2, "Resign");
        
        stateName.put(0, "Initial");
        stateName.put(1, "Learn");
        stateName.put(2, "Listen");
        stateName.put(4, "Speak");
        stateName.put(8, "Standby");
        stateName.put(16, "Active");
    }
    
    /** Default plaintext authentication key is "cisco" */
    byte[] auth = { 0x63, 0x69, 0x73, 0x63, 0x6f, 0x00, 0x00, 0x00 };
    
    InetAddress dst;
    
    int opcode, state, hellotime, holdtime, priority, group, ttl;
    
    static String USAGE = "java -jar HSRP.jar [virtual ip] {[opcode] [state] [hellotime] [holdtime] [priority] [group] [ttl]}"
            + "\nTry this: java -jar HSRP.jar [vip] 1 4 3 10 250 55 1";
    
    public static void main(String[] args) throws UnknownHostException, IOException {
        if (args.length < 1) {
            System.err.println(USAGE);
            return;
        }
        InetAddress dst = InetAddress.getByName(args[0]);
        int opcode, state, hellotime, holdtime, priority, group, ttl;
        if (args.length > 1) {
            opcode = Integer.valueOf(args[1]);
            state = Integer.valueOf(args[2]);
            hellotime = Integer.valueOf(args[3]);
            holdtime = Integer.valueOf(args[4]);
            priority = Integer.valueOf(args[5]);
            group = Integer.valueOf(args[6]);
            ttl = Integer.valueOf(args[7]);
        } else {
            opcode = 0;
            state = 0;
            hellotime = 3;
            holdtime = 10;
            priority = 100;
            group = 10;
            ttl = 1;
        }
        new Thread(HSRP::listen).start();
        ScheduledExecutorService hello = Executors.newScheduledThreadPool(5);
        HSRP hsrp = new HSRP(opcode, state, hellotime, holdtime, priority, group, ttl, dst, "cisco");
        hello.scheduleAtFixedRate(hsrp::send, 0, 3, TimeUnit.SECONDS);
    }

    public HSRP(int opcode, int state, int hellotime, int holdtime, int priority, int group, int ttl, InetAddress dst) {
        this.dst = dst;
        this.opcode = opcode;
        this.state = state;
        this.hellotime = hellotime;
        this.holdtime = holdtime;
        this.priority = priority;
        this.group = group;
        this.ttl = ttl;
    }
    
    public HSRP(int opcode, int state, int hellotime, int holdtime, int priority, int group, int ttl, InetAddress dst, String authString) {
        this(opcode, state, hellotime, holdtime, priority, group, ttl, dst);
        this.auth = Arrays.copyOfRange(authString.getBytes(), 0, 8);
        System.out.println(authString);
        System.out.println(Arrays.toString(auth));
    }
    
    byte[] newMessage() {
        if (auth.length != 8)
            throw new RuntimeException("Authentication key is not 8 bytes long: " + Arrays.toString(auth));
        
        ByteBuffer b = ByteBuffer.allocate(20);
        b.put((byte) 0); // version
        b.put((byte) opcode); // opcode
        b.put((byte) state); // state
        b.put((byte) hellotime); // hellotime
        b.put((byte) holdtime); // holdtime
        b.put((byte) priority); // priority
        b.put((byte) group); // group
        b.put((byte) 0);
        b.put(auth);
        b.put(dst.getAddress()[0]);
        b.put(dst.getAddress()[1]);
        b.put(dst.getAddress()[2]);
        b.put(dst.getAddress()[3]);
        return b.array();
    }
    
    void send() {
        byte[] data = newMessage();
        try {
            MulticastSocket socket = new MulticastSocket();
            socket.setTimeToLive(ttl);
            InetAddress allRouters = InetAddress.getByName("224.0.0.2");
            DatagramPacket packet = new DatagramPacket(data, data.length, allRouters, 1985);
            socket.send(packet);
        } catch (IOException ex) {
            System.err.println("Unable to send packet: " + ex);
        }
    }

    static void listen() {
        try (MulticastSocket socket = new MulticastSocket(1985)) {
            byte[] buffer = new byte[1500];

            InetAddress allRouters = InetAddress.getByName("224.0.0.2");
            socket.joinGroup(allRouters);

            DatagramPacket packet = new DatagramPacket(buffer, buffer.length);
            while (true) {
                socket.receive(packet);
                
                System.out.println();
                System.out.print(packet.getAddress().getHostAddress() + ": ");
                System.out.println(bytesToHex(packet.getData(), packet.getLength()));
                if (packet.getLength() < 20) {
                    System.out.println("(Discarded a small HSRP packet of length " + packet.getLength() + ".)");
                    continue; // I don't care about advertisements
                }
                ByteBuffer b = ByteBuffer.wrap(packet.getData(), 0, packet.getLength());
                byte version = b.get();
                byte op = b.get();
                byte state = b.get();
                byte hellotime = b.get();
                byte holdtime = b.get();
                byte priority = b.get();
                byte group = b.get();
                byte reserved = b.get(); // skip the reserved byte
                long auth = b.getLong();
                byte[] vip_b = new byte[]{b.get(), b.get(), b.get(), b.get()};
                InetAddress vip = InetAddress.getByAddress(vip_b);
                System.out.print("Version = " + version);
                System.out.print(", Op Code = " + opcodeName.get((int) op));
                System.out.print(", State = " + stateName.get((int) state));
                System.out.println(", Hellotime = " + Byte.toUnsignedInt(hellotime));
                System.out.print("Holdtime = " + Byte.toUnsignedInt(holdtime));
                System.out.print(", Priority = " + Byte.toUnsignedInt(priority));
                System.out.print(", Group = " + Byte.toUnsignedInt(group));
                System.out.println(", Reserved = " + reserved);
                System.out.println("Authentication Data = " + Long.toString(auth, 16) + (auth == 0x636973636f000000L ? " (default 'cisco')" : ""));
                System.out.println("Virtual IP Address = " + vip.getHostAddress());
            }
        } catch (IOException ex) {
            System.err.println("Encountered a fatal exception: " + ex);
        }
    }

    /* http://stackoverflow.com/a/9855338/5459668 */
    private final static char[] hexArray = "0123456789abcdef".toCharArray();

    /* http://stackoverflow.com/a/9855338/5459668 */
    public static String bytesToHex(byte[] bytes, int length) {
        char[] hexChars = new char[bytes.length * 2];
        for (int j = 0; j < bytes.length && j < length; j++) {
            int v = bytes[j] & 0xFF;
            hexChars[j * 2] = hexArray[v >>> 4];
            hexChars[j * 2 + 1] = hexArray[v & 0x0F];
        }
        return new String(hexChars);
    }
}
