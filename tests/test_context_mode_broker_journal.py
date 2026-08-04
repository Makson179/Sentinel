from __future__ import annotations

import json
from pathlib import Path

import pytest

from supervisor.context_mode.broker import BrokerError, BrokerJournalEntry, BrokerReceiptJournal
from supervisor.context_mode.events import ClientRole
from supervisor.context_mode.provenance import BrokerReceipt


def _entry(*, receipt_seq: int, event_seq: int, operation_id: str) -> BrokerJournalEntry:
    receipt = BrokerReceipt(
        receipt_seq=receipt_seq,
        role=ClientRole.CODER,
        app_server_instance_id="app",
        process_epoch=1,
        run_id="run",
        workspace_id="workspace",
        context_session_id="session",
        context_state_epoch=2,
        binding_version=3,
        coder_generation=1,
        generation_lease_id="lease",
        mcp_request_id=receipt_seq,
        tool_name="ctx_search",
        arguments_digest=f"{receipt_seq:064x}",
        operation_id=operation_id,
        result_digest="a" * 64,
        sandbox_backend="linux-bwrap-seccomp",
        sandbox_policy_digest="b" * 64,
        capability_id=None,
        context_event_seq=event_seq,
        duration_ms=1,
        source_bytes=0,
        returned_bytes=0,
        indexed_bytes=None,
    )
    return BrokerJournalEntry(
        logical_request_digest=f"{receipt_seq + 100:064x}",
        arguments_digest=receipt.arguments_digest,
        operation_id=operation_id,
        receipt_seq=receipt_seq,
        receipt=receipt,
        result_reference=f"result-{operation_id}",
    )


def test_broker_journal_requires_contiguous_context_event_sequence_per_epoch(
    tmp_path: Path,
) -> None:
    journal = BrokerReceiptJournal(tmp_path / "receipts.json")
    first = _entry(receipt_seq=1, event_seq=1, operation_id="operation-1")
    journal.commit(first)
    journal.commit(first)

    with pytest.raises(BrokerError, match="Context event sequence"):
        journal.commit(_entry(receipt_seq=2, event_seq=3, operation_id="operation-gap"))
    with pytest.raises(BrokerError, match="Context event sequence"):
        journal.commit(_entry(receipt_seq=2, event_seq=1, operation_id="operation-replay"))

    journal.commit(_entry(receipt_seq=2, event_seq=2, operation_id="operation-2"))
    assert BrokerReceiptJournal(tmp_path / "receipts.json").next_sequence() == 3


def test_broker_journal_rejects_persisted_receipt_or_context_sequence_gaps(
    tmp_path: Path,
) -> None:
    path = tmp_path / "receipts.json"
    journal = BrokerReceiptJournal(path)
    journal.commit(_entry(receipt_seq=1, event_seq=1, operation_id="operation-1"))
    journal.commit(_entry(receipt_seq=2, event_seq=2, operation_id="operation-2"))

    payload = json.loads(path.read_text(encoding="utf-8"))
    payload["entries"][1]["receipt_seq"] = 3
    payload["entries"][1]["receipt"]["receipt_seq"] = 3
    payload["highest_receipt_seq"] = 3
    path.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(BrokerError, match="replayed/out-of-order"):
        BrokerReceiptJournal(path)

    payload["entries"][1]["receipt_seq"] = 2
    payload["entries"][1]["receipt"]["receipt_seq"] = 2
    payload["entries"][1]["receipt"]["context_event_seq"] = 4
    payload["highest_receipt_seq"] = 2
    path.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(BrokerError, match="Context event sequence"):
        BrokerReceiptJournal(path)
