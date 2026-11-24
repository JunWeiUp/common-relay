"""Resumable chunked Box uploads (/v2/spaces/{space}/boxes/{box}/uploads)."""

from __future__ import annotations

import hashlib
import json
from typing import Any
from urllib import parse, request

from .access import ACCESS_HEADER, validate_access_password


class BoxUploadClient:
    """Thin client for Common Relay v2 resumable chunked Box uploads."""

    def __init__(
        self,
        base_url: str,
        token: str,
        *,
        password: str | None = None,
        allow_local_test: bool = False,
        timeout: float = 30.0,
    ) -> None:
        raw = base_url.rstrip("/")
        parsed = parse.urlparse(raw)
        if parsed.scheme == "http":
            if not allow_local_test or parsed.hostname not in ("127.0.0.1", "localhost", "::1"):
                raise ValueError("https is required unless allow_local_test is set for loopback")
        elif parsed.scheme != "https":
            raise ValueError("invalid base_url")
        if password:
            validate_access_password(password)
        self.base_url = raw
        self.token = token
        self.password = password or ""
        self.timeout = timeout

    def _headers(self, content_type: str | None = None) -> dict[str, str]:
        h = {"Authorization": f"Bearer {self.token}"}
        if self.password:
            h[ACCESS_HEADER] = self.password
        if content_type:
            h["Content-Type"] = content_type
        return h

    def _uploads_url(self, space_id: str, box_name: str, suffix: str = "") -> str:
        sp = parse.quote(space_id, safe="")
        box = "/".join(parse.quote(seg, safe="") for seg in box_name.split("/"))
        return f"{self.base_url}/v2/spaces/{sp}/boxes/{box}/uploads{suffix}"

    def _req_json(self, method: str, url: str, body: dict[str, Any] | None = None) -> dict[str, Any]:
        data = json.dumps(body).encode("utf-8") if body is not None else None
        req = request.Request(
            url,
            data=data,
            headers=self._headers("application/json" if body is not None else None),
            method=method,
        )
        with request.urlopen(req, timeout=self.timeout) as resp:
            raw = resp.read()
            return json.loads(raw.decode("utf-8")) if raw else {"ok": True}

    def create_upload(
        self,
        space_id: str,
        box_name: str,
        total_size: int,
        *,
        key: str = "",
        content_type: str = "application/octet-stream",
        meta_json: str = "{}",
        ttl_seconds: int = 0,
    ) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "total_size": total_size,
            "content_type": content_type,
            "meta": meta_json,
        }
        if key:
            payload["key"] = key
        if ttl_seconds > 0:
            payload["ttl"] = ttl_seconds
        return self._req_json("POST", self._uploads_url(space_id, box_name), payload)["upload"]

    def get_upload(self, space_id: str, box_name: str, upload_id: str) -> dict[str, Any]:
        url = self._uploads_url(space_id, box_name, f"/{parse.quote(upload_id, safe='')}")
        return self._req_json("GET", url)["upload"]

    def append_chunk(
        self, space_id: str, box_name: str, upload_id: str, offset: int, chunk: bytes
    ) -> dict[str, Any]:
        url = self._uploads_url(space_id, box_name, f"/{parse.quote(upload_id, safe='')}?offset={offset}")
        req = request.Request(
            url,
            data=chunk,
            headers=self._headers("application/octet-stream"),
            method="PATCH",
        )
        with request.urlopen(req, timeout=self.timeout) as resp:
            return json.loads(resp.read().decode("utf-8"))["upload"]

    def complete_upload(
        self,
        space_id: str,
        box_name: str,
        upload_id: str,
        *,
        sha256_hex: str = "",
        expected_etag: str = "",
    ) -> dict[str, Any]:
        url = self._uploads_url(space_id, box_name, f"/{parse.quote(upload_id, safe='')}/complete")
        body: dict[str, Any] = {}
        if sha256_hex:
            body["sha256"] = sha256_hex
        if expected_etag:
            body["expected_etag"] = expected_etag
        return self._req_json("POST", url, body)

    def abort_upload(self, space_id: str, box_name: str, upload_id: str) -> None:
        url = self._uploads_url(space_id, box_name, f"/{parse.quote(upload_id, safe='')}")
        self._req_json("DELETE", url)

    def upload_resumable(
        self,
        space_id: str,
        box_name: str,
        data: bytes,
        *,
        key: str = "",
        content_type: str = "application/octet-stream",
        meta_json: str = "{}",
        chunk_size: int = 256 * 1024,
        ttl_seconds: int = 0,
        expected_etag: str = "",
    ) -> dict[str, Any]:
        digest = hashlib.sha256(data).hexdigest()
        up = self.create_upload(
            space_id,
            box_name,
            len(data),
            key=key,
            content_type=content_type,
            meta_json=meta_json,
            ttl_seconds=ttl_seconds,
        )
        upload_id = up["id"]
        offset = 0
        while offset < len(data):
            chunk = data[offset : offset + chunk_size]
            up = self.append_chunk(space_id, box_name, upload_id, offset, chunk)
            offset = int(up["offset"])
        return self.complete_upload(
            space_id,
            box_name,
            upload_id,
            sha256_hex=digest,
            expected_etag=expected_etag,
        )
