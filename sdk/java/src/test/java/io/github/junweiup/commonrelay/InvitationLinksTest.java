package io.github.junweiup.commonrelay;
import org.junit.Test;
import static org.junit.Assert.*;
import org.json.JSONObject;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
public class InvitationLinksTest {
 /** Field-by-field equality of flat JSON objects (Android's org.json lacks similar()). */
 private static void assertSame(JSONObject want,JSONObject got)throws Exception{
  java.util.Set<String> keys=new java.util.TreeSet<>();for(java.util.Iterator<String> it=want.keys();it.hasNext();)keys.add(it.next());
  java.util.Set<String> gotKeys=new java.util.TreeSet<>();for(java.util.Iterator<String> it=got.keys();it.hasNext();)gotKeys.add(it.next());
  assertEquals(keys,gotKeys);for(String k:keys)assertEquals(k,String.valueOf(want.get(k)),String.valueOf(got.get(k)));
 }
 @Test public void sharedPacketAndTampering()throws Exception{
  JSONObject v=new JSONObject(new String(Files.readAllBytes(Path.of("../../protocol/v2/invitation-link-vectors.json")),StandardCharsets.UTF_8));byte[] key=Crypto.unhex(v.getString("key")),nonce=Crypto.unhex(v.getString("nonce"));JSONObject inv=InvitationLinks.open(v.getString("packet"),key);
  String link=v.getString("link"),linkWithPassword=v.getString("link_with_password");
  assertSame(v.getJSONObject("invitation"),inv);
  assertEquals("wss://relay.example.com/v2/ws",inv.getString("url"));
  // The packet decrypts to exactly packet_plaintext.
  byte[] raw=CanonicalBase64.decode(v.getString("packet"));assertArrayEquals(nonce,Arrays.copyOf(raw,24));
  byte[] cipher=Arrays.copyOfRange(raw,24,raw.length),plain=new byte[cipher.length-16];
  Crypto.check(Crypto.S.crypto_secretbox_open_easy(plain,cipher,cipher.length,nonce,key));
  assertEquals(v.getString("packet_plaintext"),new String(plain,StandardCharsets.UTF_8));
  assertEquals(v.getString("read_token"),InvitationLinks.readToken(key));
  assertEquals(v.getString("read_hash"),V2Client.hashSecret(v.getString("read_token")));
  assertEquals(link,InvitationLinks.make(inv,key));assertEquals(v.getInt("link_length"),link.length());
  assertEquals(inv.getString("url"),InvitationLinks.parse(link,false).url);
  assertEquals("ws://127.0.0.1:9/v2/ws",InvitationLinks.parse(link.replace("relay.example.com","127.0.0.1:9"),true).url);
  // seal() serializes via org.json (unordered keys), so only the round trip is deterministic.
  assertSame(inv,InvitationLinks.open(InvitationLinks.seal(inv,key,nonce),key));
  assertThrows(Exception.class,()->InvitationLinks.open(v.getString("packet"),new byte[32]));
  assertNull(InvitationLinks.parse(link,false).password);
  assertEquals(linkWithPassword,InvitationLinks.make(inv,key,v.getString("access_password")));
  InvitationLinks.Parsed withPassword=InvitationLinks.parse(linkWithPassword,false);
  assertEquals(v.getString("access_password"),withPassword.password);assertArrayEquals(key,withPassword.key);assertEquals(inv.getString("id"),withPassword.id);
  org.json.JSONArray bad=v.getJSONArray("invalid_link_suffixes");
  for(int i=0;i<bad.length();i++){String suffix=bad.getString(i);assertThrows(suffix,Exception.class,()->InvitationLinks.parse(link+suffix,false));}
  org.json.JSONArray invalid=v.getJSONArray("invalid_links");assertTrue(invalid.length()>0);
  for(int i=0;i<invalid.length();i++){String l=invalid.getString(i);assertThrows(l,Exception.class,()->InvitationLinks.parse(l,false));}
 }
}
