package io.github.junweiup.commonrelay;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.fail;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import org.junit.Test;

public class GroupStateMachineTest {
    @Test
    public void draftPersistedBeforeNetworkAndClearedOnCommit() throws Exception {
        final List<String> trace = new ArrayList<>();
        final String[] stored = new String[1];
        final Integer[] committed = new Integer[1];

        GroupStateMachine<Integer> sm = new GroupStateMachine<>(new GroupStateMachine.DraftStore<Integer>() {
            @Override
            public void saveDraft(GroupStateMachine.GroupDraft draft) throws Exception {
                trace.add("save");
                stored[0] = draft.encodeJson();
            }

            @Override
            public GroupStateMachine.GroupDraft loadDraft() throws Exception {
                return stored[0] == null ? null : GroupStateMachine.GroupDraft.decodeJson(stored[0]);
            }

            @Override
            public void commit(GroupStateMachine.GroupDraft draft, Integer result) {
                trace.add("commit");
                committed[0] = result;
            }

            @Override
            public void clearDraft(String draftId) {
                trace.add("clear");
                stored[0] = null;
            }
        });

        GroupStateMachine.GroupDraft draft = new GroupStateMachine.GroupDraft(
                "d1", "create", "wifiadb", "g1", "phone",
                "0000000000000000000000000000000000000000000000000000000000000000",
                "1111111111111111111111111111111111111111111111111111111111111111",
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "", 1700000000L);

        try {
            sm.execute(draft, d -> {
                throw new RuntimeException("timeout");
            });
            fail("expected exception");
        } catch (RuntimeException expected) {
            // expected
        }
        assertNotNull(sm.pendingDraft());
        assertEquals("d1", sm.pendingDraft().draftId);
        assertNull(committed[0]);

        Integer rev = sm.execute(sm.pendingDraft(), d -> 4);
        assertEquals(Integer.valueOf(4), rev);
        assertNull(sm.pendingDraft());
        assertEquals(Integer.valueOf(4), committed[0]);
        assertEquals(Arrays.asList("save", "save", "commit", "clear"), trace);
    }

    @Test
    public void directUpgradeRoundtrip() throws Exception {
        assertEquals("relay.direct.v1", GroupStateMachine.DIRECT_UPGRADE_TOPIC);
        GroupStateMachine.DirectUpgradeMessage msg = new GroupStateMachine.DirectUpgradeMessage(
                "offer", "s1", Collections.singletonList("192.168.1.3:47899"), "f00d");
        GroupStateMachine.DirectUpgradeMessage dec =
                GroupStateMachine.DirectUpgradeMessage.decode(msg.encode());
        assertEquals("offer", dec.op);
        assertEquals("s1", dec.session);
        assertEquals(Collections.singletonList("192.168.1.3:47899"), dec.candidates);
        assertEquals("f00d", dec.nonce);
    }
}
