package io.github.junweiup.commonrelay;
import org.junit.Test;
import org.junit.Assume;
import static org.junit.Assert.*;
import org.json.JSONObject;
import okhttp3.OkHttpClient;
import java.nio.file.*;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicReference;
public class InteropTest {
    @Test public void liveEcho()throws Exception {
        String path=System.getenv("COMMON_RELAY_QA_CONFIG");Assume.assumeTrue(path!=null);
        JSONObject c=new JSONObject(new String(Files.readAllBytes(Path.of(path)),StandardCharsets.UTF_8));Map<String,String> peers=new HashMap<>();JSONObject trusted=c.getJSONObject("trusted_peers");for(Iterator<String> it=trusted.keys();it.hasNext();){String name=it.next();peers.put(name,trusted.getString(name));}
        Crypto crypto=new Crypto(c.getString("app"),c.getString("group"),c.getString("device"),c.getString("secret_key"),peers);
        CountDownLatch done=new CountDownLatch(1);AtomicReference<Throwable> failure=new AtomicReference<>();ExecutorService worker=Executors.newSingleThreadExecutor();OkHttpClient.Builder builder=new OkHttpClient.Builder().pingInterval(20,TimeUnit.SECONDS);String proxy=System.getenv("HTTPS_PROXY");if(proxy!=null&&!c.optBoolean("allow_local_test")){java.net.URI u=java.net.URI.create(proxy);builder.proxy(new java.net.Proxy(java.net.Proxy.Type.HTTP,new java.net.InetSocketAddress(u.getHost(),u.getPort())));}OkHttpClient http=builder.build();RelayClient[] holder=new RelayClient[1];
        RelayClient client=new RelayClient(http,crypto,new RelayClient.Listener(){
            public void onReady(){System.out.println("READY");}
            public void onClosed(Throwable error){System.out.println("CLOSED "+error.getClass().getSimpleName());}
            public void onEvent(JSONObject e){worker.execute(()->{try{
                if(e.getString("type").equals("message")){holder[0].message(e.getString("from"),Base64.getDecoder().decode(e.getString("data")),e.optBoolean("offline"),null).get(15,TimeUnit.SECONDS);if(e.optBoolean("offline"))holder[0].acknowledge(e).get(15,TimeUnit.SECONDS);}
                else if(e.getString("type").equals("stream.open")){RelayClient.Stream stream=holder[0].acceptStream(e).get(45,TimeUnit.SECONDS);while(!stream.receivedFinal()){byte[] data=stream.receive();stream.send(data,stream.receivedFinal());}Thread.sleep(1500);done.countDown();}
            }catch(Throwable error){failure.set(error);done.countDown();}});}
        },c.has("state_path")?new RelayJournal(Path.of(c.getString("state_path"))):null);holder[0]=client;
        try{client.connect(c.getString("url"),c.getString("token"),c.optBoolean("allow_local_test"));assertTrue("Interop timeout",done.await(120,TimeUnit.SECONDS));if(failure.get()!=null)throw new AssertionError(failure.get());}
        finally{client.close();worker.shutdownNow();http.dispatcher().executorService().shutdown();http.connectionPool().evictAll();}
    }
}
