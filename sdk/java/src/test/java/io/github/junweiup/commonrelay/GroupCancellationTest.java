package io.github.junweiup.commonrelay;

import org.json.JSONObject;
import org.junit.Test;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;
import static org.junit.Assert.*;

public class GroupCancellationTest {
    /** Accepts connections and never answers, counting how many arrived. */
    private static ServerSocket hanging(AtomicInteger hits,CountDownLatch started,java.util.List<Socket> held)throws Exception{
        ServerSocket server=new ServerSocket(0,50,InetAddress.getByName("127.0.0.1"));
        Thread t=new Thread(()->{try{while(true){Socket s=server.accept();held.add(s);hits.incrementAndGet();started.countDown();}}catch(Exception ignored){}});
        t.setDaemon(true);t.start();return server;
    }
    private static String url(ServerSocket s){return "ws://127.0.0.1:"+s.getLocalPort()+"/relay/v1/ws";}

    @Test public void interruptCancelsInFlightRequest()throws Exception{
        AtomicInteger hits=new AtomicInteger();CountDownLatch started=new CountDownLatch(1);java.util.List<Socket> held=new CopyOnWriteArrayList<>();
        try(ServerSocket server=hanging(hits,started,held)){
            RelayGroups groups=new RelayGroups(new JSONObject().put("url",url(server)).put("app","test").put("device","test"),true);
            ExecutorService pool=Executors.newSingleThreadExecutor();
            Future<?> f=pool.submit(()->{groups.call("GET","/group",null,null);return null;});
            assertTrue(started.await(5,TimeUnit.SECONDS));
            long t0=System.nanoTime();f.cancel(true);pool.shutdown();
            assertTrue("worker did not stop",pool.awaitTermination(2,TimeUnit.SECONDS));
            assertTrue(System.nanoTime()-t0<TimeUnit.SECONDS.toNanos(2));
            for(Socket s:held)s.close();
        }
    }

    @Test public void interruptedResolutionNeverContactsRelay()throws Exception{
        AtomicInteger hits=new AtomicInteger();java.util.List<Socket> held=new CopyOnWriteArrayList<>();
        try(ServerSocket server=hanging(hits,new CountDownLatch(1),held)){
            RelayGroups groups=new RelayGroups(new JSONObject().put("url",url(server)).put("app","example"),true);
            String link=InvitationLinks.make(new JSONObject().put("url",url(server)).put("id","a".repeat(32)),new byte[32]);
            Thread.currentThread().interrupt();
            try{assertThrows(InterruptedException.class,()->groups.resolveInvitation(link));}
            finally{Thread.interrupted();}
            Thread.sleep(100);assertEquals(0,hits.get());
        }
    }
}
