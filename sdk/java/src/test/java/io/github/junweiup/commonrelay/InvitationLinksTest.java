package io.github.junweiup.commonrelay;
import org.junit.Test;
import static org.junit.Assert.*;
import org.json.JSONObject;
import java.nio.file.Files;
import java.nio.file.Path;
public class InvitationLinksTest {
 @Test public void sharedPacketAndTampering()throws Exception{
  JSONObject v=new JSONObject(new String(Files.readAllBytes(Path.of("../../protocol/invitation-link-vectors.json")),java.nio.charset.StandardCharsets.UTF_8));byte[] key=Crypto.unhex(v.getString("key"));JSONObject inv=InvitationLinks.open(v.getString("packet"),key);
  // The shared vectors carry a pre-v2 URL; relays now serve only /v2/ws and "/v2/i/" short links.
  String link=AccessTest.v2Link(v,"link"),linkWithPassword=AccessTest.v2Link(v,"link_with_password");
  assertThrows(Exception.class,()->InvitationLinks.make(inv,key));
  assertThrows("pre-v2 short links are rejected",Exception.class,()->InvitationLinks.parse(v.getString("link"),false));
  inv.put("url",inv.getString("url").replace("/relay/v1/ws","/v2/ws"));
  assertEquals(v.getJSONObject("invitation").getString("id"),inv.getString("id"));assertEquals(v.getString("read_token"),InvitationLinks.readToken(key));assertEquals(link,InvitationLinks.make(inv,key));assertEquals(inv.getString("url"),InvitationLinks.parse(link,false).url);
  assertEquals("ws://127.0.0.1:9/v2/ws",InvitationLinks.parse(link.replace("relay.example.com","127.0.0.1:9"),true).url);
  assertEquals(inv.getString("id"),InvitationLinks.open(InvitationLinks.seal(inv,key,Crypto.unhex(v.getString("nonce"))),key).getString("id"));
  assertThrows(Exception.class,()->InvitationLinks.open(v.getString("packet"),new byte[32]));
  assertThrows(Exception.class,()->InvitationLinks.parse(link+"=",false));
  assertThrows(Exception.class,()->InvitationLinks.parse(link.replace("relay.example.com","user@relay.example.com"),false));
  assertNull(InvitationLinks.parse(link,false).password);
  assertEquals(linkWithPassword,InvitationLinks.make(inv,key,v.getString("access_password")));
  InvitationLinks.Parsed withPassword=InvitationLinks.parse(linkWithPassword,false);
  assertEquals(v.getString("access_password"),withPassword.password);assertArrayEquals(key,withPassword.key);assertEquals(inv.getString("id"),withPassword.id);
  org.json.JSONArray bad=v.getJSONArray("invalid_link_suffixes");
  for(int i=0;i<bad.length();i++){String suffix=bad.getString(i);assertThrows(suffix,Exception.class,()->InvitationLinks.parse(link+suffix,false));}
 }
}
