import unittest

from common_relay.state_machine import (
    DIRECT_UPGRADE_TOPIC,
    DirectUpgradeMessage,
    GroupDraft,
    GroupStateMachine,
)


class StateMachineTests(unittest.TestCase):
    def test_draft_persisted_before_network_and_cleared_on_commit(self):
        log = []
        stored = {}

        def save_draft(d: GroupDraft):
            log.append(("save", d.draft_id))
            stored["draft"] = d.to_json()

        def commit(d: GroupDraft, res):
            log.append(("commit", d.draft_id, res))
            stored["committed"] = res

        def clear_draft(did: str):
            log.append(("clear", did))
            stored.pop("draft", None)

        def load_draft():
            raw = stored.get("draft")
            return GroupDraft.from_json(raw) if raw else None

        sm = GroupStateMachine(
            save_draft=save_draft,
            commit=commit,
            clear_draft=clear_draft,
            load_draft=load_draft,
        )
        draft = GroupDraft(
            draft_id="d1",
            op="create",
            app="demo",
            group="g1",
            device="dev1",
            secret_key="00" * 32,
            sign_secret_key="11" * 32,
            token="a" * 64,
        )

        # Simulated crash during network action must keep draft intact.
        def failing_action(_d):
            log.append(("net_fail", _d.draft_id))
            raise RuntimeError("network timeout")

        with self.assertRaises(RuntimeError):
            sm.execute(draft, failing_action)
        self.assertIsNotNone(sm.pending_draft())
        self.assertEqual(sm.pending_draft().draft_id, "d1")
        self.assertNotIn("committed", stored)

        # Retry succeeds, commits, and clears draft.
        res = sm.execute(sm.pending_draft(), lambda _d: {"revision": 1})
        self.assertEqual(res, {"revision": 1})
        self.assertIsNone(sm.pending_draft())
        self.assertEqual(stored["committed"], {"revision": 1})
        self.assertEqual([e[0] for e in log], ["save", "net_fail", "save", "commit", "clear"])

    def test_direct_upgrade_roundtrip(self):
        self.assertEqual(DIRECT_UPGRADE_TOPIC, "relay.direct.v1")
        msg = DirectUpgradeMessage(
            op="offer",
            session="abc123",
            candidates=["192.168.1.10:47899"],
            nonce="deadbeef",
        )
        raw = msg.encode()
        dec = DirectUpgradeMessage.decode(raw)
        self.assertEqual(dec, msg)
        with self.assertRaises(ValueError):
            DirectUpgradeMessage(op="bogus", session="s1").encode()


if __name__ == "__main__":
    unittest.main()
