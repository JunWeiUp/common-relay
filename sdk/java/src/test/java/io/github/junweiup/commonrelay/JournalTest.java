package io.github.junweiup.commonrelay;
import org.junit.Test;
import static org.junit.Assert.*;
import java.nio.file.*;
import java.util.concurrent.atomic.AtomicLong;
import java.util.Comparator;
import org.json.JSONObject;
public class JournalTest {
 @Test public void restartExpiryAndCleanup()throws Exception{
  Path dir=Files.createTempDirectory("relay-journal");AtomicLong now=new AtomicLong(1000000);
  try{
   RelayJournal j=new RelayJournal(dir,now::get);byte[] data="hello".getBytes();
   JSONObject first=j.prepare("a","id","b",data,60,e->"cipher");now.addAndGet(30);j=new RelayJournal(dir,now::get);
   JSONObject retry=j.prepare("a","id","b",data,86400,e->{throw new AssertionError("reencryption");});
   assertEquals(first.getString("body"),retry.getString("body"));assertEquals(first.getLong("expires"),retry.getLong("expires"));
   final RelayJournal state=j;
   assertThrows(Exception.class,()->state.prepare("a","id","b",new byte[0],60,e->"bad"));
   j.acknowledge("a","b","in");assertTrue(j.contains("a","b","in"));assertFalse(j.contains("other","b","in"));
   now.addAndGet(30);j.cleanup();assertThrows(Exception.class,()->state.prepare("a","id","b",data,60,e->"bad"));
   try(var paths=Files.list(dir)){for(Path p:paths.toList())assertFalse(new String(Files.readAllBytes(p),java.nio.charset.StandardCharsets.UTF_8).contains("cipher"));}
   now.addAndGet(7*86400);j.cleanup();try(var paths=Files.list(dir)){assertEquals(0,paths.count());}
   j.prepare("a","complete","b",data,60,e->"cipher");j.complete("a","complete");assertFalse(j.prepare("a","complete","b",data,60,e->"bad").has("body"));
  }finally{try(var paths=Files.walk(dir)){for(Path p:paths.sorted(Comparator.reverseOrder()).toList())Files.deleteIfExists(p);}}
 }
}
