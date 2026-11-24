"""Callback-driven draft-before-send group state machine and direct-upgrade helpers."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
import json
import time
from typing import Any, Callable, Optional


DIRECT_UPGRADE_TOPIC = "relay.direct.v1"


@dataclass
class GroupDraft:
    """Pending credential/mutation draft persisted BEFORE issuing network requests."""

    draft_id: str
    op: str  # "create" | "join" | "auto_join" | "rotate"
    app: str
    group: str
    device: str
    secret_key: str
    sign_secret_key: str
    token: str
    invite_id: str = ""
    created_at: int = field(default_factory=lambda: int(time.time()))

    def to_json(self) -> str:
        return json.dumps(asdict(self), sort_keys=True, separators=(",", ":"))

    @classmethod
    def from_json(cls, raw: str) -> "GroupDraft":
        data = json.loads(raw)
        return cls(**data)


class GroupStateMachine:
    """Coordinates draft-before-send mutations so crashes mid-flight never lose keys.

    Callers supply thin persistence callbacks (`save_draft`, `commit`, `clear_draft`,
    and optional `load_draft`) backed by their own secure store (Keychain, SQLite, etc.).
    """

    def __init__(
        self,
        *,
        save_draft: Callable[[GroupDraft], None],
        commit: Callable[[GroupDraft, Any], None],
        clear_draft: Callable[[str], None],
        load_draft: Optional[Callable[[], Optional[GroupDraft]]] = None,
    ) -> None:
        self._save_draft = save_draft
        self._commit = commit
        self._clear_draft = clear_draft
        self._load_draft = load_draft

    def pending_draft(self) -> Optional[GroupDraft]:
        return self._load_draft() if self._load_draft is not None else None

    def execute(self, draft: GroupDraft, action: Callable[[GroupDraft], Any]) -> Any:
        """Persist `draft` first, execute `action(draft)`, then commit and clear."""
        self._save_draft(draft)
        result = action(draft)
        self._commit(draft, result)
        self._clear_draft(draft.draft_id)
        return result


@dataclass
class DirectUpgradeMessage:
    """Plaintext payload carried inside a §6 encrypted envelope on DIRECT_UPGRADE_TOPIC."""

    op: str  # "offer" | "answer" | "fallback"
    session: str
    candidates: list[str] = field(default_factory=list)
    nonce: str = ""

    def validate(self) -> None:
        if self.op not in ("offer", "answer", "fallback"):
            raise ValueError(f"invalid direct upgrade op: {self.op!r}")
        if not self.session or not self.session.strip():
            raise ValueError("direct upgrade session is required")

    def encode(self) -> bytes:
        self.validate()
        obj: dict[str, Any] = {"op": self.op, "session": self.session}
        if self.candidates:
            obj["candidates"] = list(self.candidates)
        if self.nonce:
            obj["nonce"] = self.nonce
        return json.dumps(obj, separators=(",", ":")).encode("utf-8")

    @classmethod
    def decode(cls, raw: bytes | str) -> "DirectUpgradeMessage":
        data = json.loads(raw.decode("utf-8") if isinstance(raw, (bytes, bytearray)) else raw)
        msg = cls(
            op=data.get("op", ""),
            session=data.get("session", ""),
            candidates=list(data.get("candidates") or []),
            nonce=data.get("nonce", ""),
        )
        msg.validate()
        return msg
