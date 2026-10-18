package io.github.junweiup.commonrelay;
import org.junit.Test;
import org.junit.Assume;
import org.json.JSONObject;
import java.nio.file.*;
import java.nio.charset.StandardCharsets;
public class GroupInteropTest {
 @Test public void groupOperation()throws Exception {
  String path=System.getenv("COMMON_RELAY_GROUP_CONFIG");Assume.assumeTrue(path!=null);
  JSONObject c=new JSONObject(new String(Files.readAllBytes(Path.of(path)),StandardCharsets.UTF_8));RelayGroups g=new RelayGroups(c,true);Object result=new JSONObject();
  switch(c.getString("group_action")){
   case "rename":g.rename(c.getString("device"),"Updated device");break;
   case "leave":g.prepareExit(false);g.exit();break;
   case "disband":g.prepareExit(true);g.exit();break;
   case "create":c.remove("group");g.prepareCreate("My devices","Creator");g.create();break;
   case "join":g.join(c.has("invitation_link")?g.resolveInvitation(c.getString("invitation_link")):c.getJSONObject("invitation"),c.getString("device"));break;
   case "finish":result=g.finishJoin();break;
   case "invite":result=g.invite(c.optString("invite_mode","manual"),c.optBoolean("compact"));break;
   case "approve":g.approve(c.getJSONObject("invitation"),c.getJSONObject("request"),false);break;
   case "remove":g.remove(c.getString("remove"));break;
   default:result=g.refresh();
  }
  g.config.put("result",result);Files.write(Path.of(path),g.config.toString().getBytes(StandardCharsets.UTF_8));
 }
}
