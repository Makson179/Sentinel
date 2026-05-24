from __future__ import annotations

import json
import socket
from pathlib import Path

from supervisor.schemas import IPCRequest, IPCResponse


def send_ipc_request(socket_path: str | Path, request: IPCRequest, timeout_seconds: float = 10.0) -> IPCResponse:
    payload = request.model_dump_json().encode("utf-8") + b"\n"
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
        client.settimeout(timeout_seconds)
        client.connect(str(socket_path))
        client.sendall(payload)
        chunks: list[bytes] = []
        while True:
            chunk = client.recv(65536)
            if not chunk:
                break
            chunks.append(chunk)
            if b"\n" in chunk:
                break
    raw = b"".join(chunks).split(b"\n", 1)[0]
    return IPCResponse.model_validate(json.loads(raw.decode("utf-8")))

