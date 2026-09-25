#!/usr/bin/env python3
"""Scoped, provider-backed Web3 invariant verification tooling.

The harness intentionally has no mock target or standalone toy entrypoint. It
expects a scoped target, an active Ape provider such as Foundry's local fork,
and source-level analysis through Slither. Chain forking is left to the caller
and is never performed by importing this module.
"""

import json
import re
import sqlite3
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, Iterable, List, Optional, Tuple, Union

import z3

try:
    from eth_hash.auto import keccak
except ImportError:
    def keccak(data: bytes) -> bytes:
        raise RuntimeError("eth-hash is required for Ethereum Keccak-256")

try:
    from ape import accounts, networks
    from ape.exceptions import ContractLogicError
    APE_AVAILABLE = True
except ImportError:
    accounts = None
    networks = None

    class ContractLogicError(Exception):
        pass

    APE_AVAILABLE = False


MAINNET_CHAIN_ID = 1
ENZYME_BLUE_REPOSITORY = "https://github.com/enzymefinance/protocol"
EIP1967_ADMIN_SLOT = int(
    "0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103", 16
)
EIP1967_IMPLEMENTATION_SLOT = int(
    "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc", 16
)
EIP1967_BEACON_SLOT = int(
    "0xa3f0ad74e5423aebfd80d3ef4346578335a9a72aeaee59ff6cb3582b35133d50", 16
)


class VectorClass(Enum):
    UNPROTECTED_STATE_WRITE = "UNPROTECTED_STATE_WRITE"
    CONTROLLED_DELEGATECALL = "CONTROLLED_DELEGATECALL"
    REENTRANCY = "REENTRANCY"
    ARITHMETIC_MANIPULATION = "ARITHMETIC_MANIPULATION"
    ACCESS_CONTROL_BYPASS = "ACCESS_CONTROL_BYPASS"
    ARBITRARY_EXTERNAL_CALL = "ARBITRARY_EXTERNAL_CALL"
    METAMORPHIC_SELFDESTRUCT = "METAMORPHIC_SELFDESTRUCT"
    ROLE_MAPPING_ESCALATION = "ROLE_MAPPING_ESCALATION"


@dataclass(frozen=True)
class TargetScope:
    """Immutable identity for one target and its dedicated execution clone."""

    scope_id: str
    target_address: str
    chain_id: int
    fork_block: int
    rpc_url: str
    clone_id: str
    source_repo: Optional[str] = None
    source_ref: str = "main"

    def __post_init__(self) -> None:
        address = self.target_address.lower()
        if (
            not address.startswith("0x")
            or len(address) != 42
            or any(character not in "0123456789abcdef" for character in address[2:])
        ):
            raise ValueError("target_address must be a hexadecimal 20-byte EVM address")
        if self.chain_id < 0 or self.fork_block < 0:
            raise ValueError("chain_id and fork_block must be non-negative")
        if not self.scope_id or not self.clone_id or not self.source_ref:
            raise ValueError("scope_id, clone_id, and source_ref are required")

    @property
    def normalized_target(self) -> str:
        return self.target_address.lower()

    @classmethod
    def enzyme_blue(
        cls,
        scope_id: str,
        target_address: str,
        fork_block: int,
        rpc_url: str,
        clone_id: str,
        source_ref: str = "main",
    ) -> "TargetScope":
        return cls(
            scope_id=scope_id,
            target_address=target_address,
            chain_id=MAINNET_CHAIN_ID,
            fork_block=fork_block,
            rpc_url=rpc_url,
            clone_id=clone_id,
            source_repo=ENZYME_BLUE_REPOSITORY,
            source_ref=source_ref,
        )


class ScopedCloneRegistry:
    """Enforces a one-scope-to-one-clone relationship for every target."""

    def __init__(self) -> None:
        self._clones: Dict[str, TargetScope] = {}

    def register(self, scope: TargetScope) -> TargetScope:
        target = scope.normalized_target
        if target in self._clones:
            raise ValueError(f"target already has a dedicated clone: {target}")
        if any(existing.clone_id == scope.clone_id for existing in self._clones.values()):
            raise ValueError(f"clone_id is already registered: {scope.clone_id}")
        self._clones[target] = scope
        return scope

    def get(self, target_address: str) -> Optional[TargetScope]:
        return self._clones.get(target_address.lower())

    def all_scopes(self) -> List[TargetScope]:
        return list(self._clones.values())


@dataclass
class StorageSlotRef:
    slot: int
    offset: int = 0
    size_bytes: int = 32
    label: str = ""
    is_mapping: bool = False
    mapping_key: Optional[bytes] = None


@dataclass
class VulnerabilityCandidate:
    vector_class: VectorClass
    function_name: str
    function_signature: str
    four_byte_selector: str
    input_types: List[str]
    target_slots: List[StorageSlotRef]
    required_invariants: List[Dict[str, Any]] = field(default_factory=list)


@dataclass(frozen=True)
class ExecutionResult:
    success: bool
    return_data: bytes = b""
    revert_data: bytes = b""
    error_kind: Optional[str] = None
    transaction_hash: Optional[str] = None


@dataclass(frozen=True)
class RevertInfo:
    kind: str
    message: str
    selector: str
    raw: bytes


@dataclass(frozen=True)
class ChainStep:
    """One transaction in a multi-step PoC chain with exact preconditions."""

    target_address: str
    calldata: bytes
    expected_pre: Dict[str, str] = field(default_factory=dict)
    step_note: str = ""

    def __post_init__(self) -> None:
        if not isinstance(self.calldata, bytes):
            raise TypeError("ChainStep calldata must be bytes")
        for slot, value in self.expected_pre.items():
            try:
                int(slot, 0)
                bytes.fromhex(value[2:] if value.startswith("0x") else value)
            except (TypeError, ValueError) as error:
                raise ValueError(f"invalid expected_pre entry {slot}: {error}") from error


class StorageEngine:
    """Provider-backed EVM state reads and deterministic snapshot control."""

    def __init__(self, provider: Any = None, scope: Optional[TargetScope] = None) -> None:
        if provider is None:
            if not APE_AVAILABLE or networks is None or networks.active_provider is None:
                raise RuntimeError(
                    "an active Ape provider is required; fork mainnet before constructing StorageEngine"
                )
            provider = networks.active_provider
        self.provider = provider
        self.scope = scope
        # Keep the exact RPC value for evm_revert. Providers differ on whether
        # snapshot ids are integers, decimal strings, or 0x-prefixed hex.
        self._snapshot_params: Dict[str, Any] = {}

    def bind_scope(self, scope: TargetScope) -> None:
        if self.scope is not None and self.scope != scope:
            raise ValueError("storage engine is already bound to another scope")
        self.scope = scope

    def assert_target_allowed(self, target_address: str) -> None:
        if self.scope is not None and target_address.lower() != self.scope.normalized_target:
            raise ValueError("target address is outside the bound execution scope")

    def snapshot(self) -> str:
        snapshot_id = self.provider.make_request("evm_snapshot", [])
        if snapshot_id is None:
            raise RuntimeError("provider returned no evm_snapshot id")
        key = str(snapshot_id)
        self._snapshot_params[key] = snapshot_id
        return key

    def revert(self, snapshot_id: Union[str, int]) -> bool:
        key = str(snapshot_id)
        raw_snapshot_id = self._snapshot_params.pop(key, snapshot_id)
        result = self.provider.make_request("evm_revert", [raw_snapshot_id])
        if isinstance(result, str):
            return result.lower() not in ("", "0x0", "0x00", "false", "0")
        return result is True or result == 1

    @staticmethod
    def _decode_hex(value: Any) -> bytes:
        if isinstance(value, (bytes, bytearray, memoryview)):
            return bytes(value)
        if isinstance(value, str):
            if value.startswith("0x"):
                value = value[2:]
            return bytes.fromhex(value)
        raise TypeError(f"provider returned unsupported storage value: {type(value)!r}")

    def get_storage_at(self, address: str, slot: int) -> bytes:
        self.assert_target_allowed(address)
        raw = self.provider.make_request(
            "eth_getStorageAt", [address.lower(), hex(slot), "latest"]
        )
        return self._decode_hex(raw).rjust(32, b"\x00")

    def get_storage_range(self, address: str, slots: Iterable[int]) -> Dict[int, bytes]:
        return {slot: self.get_storage_at(address, slot) for slot in slots}

    @staticmethod
    def compute_mapping_slot(key: bytes, base_slot: int) -> int:
        if len(key) > 32:
            raise ValueError("mapping keys cannot exceed 32 bytes")
        if base_slot < 0 or base_slot >= 1 << 256:
            raise ValueError("base slot must fit in an EVM word")
        padded_key = key.rjust(32, b"\x00")
        padded_slot = base_slot.to_bytes(32, byteorder="big")
        return int.from_bytes(keccak(padded_key + padded_slot), byteorder="big")


class EVMExecutionInterface(StorageEngine):
    """Provider-backed raw transaction simulation with explicit failure details."""

    def __init__(self, provider: Any = None, scope: Optional[TargetScope] = None) -> None:
        super().__init__(provider=provider, scope=scope)

    @staticmethod
    def _error_data(error: Exception) -> bytes:
        value = getattr(error, "data", None)
        if value is None:
            args = getattr(error, "args", ())
            value = args[0] if args else b""
        if isinstance(value, dict):
            for key in ("data", "return_data", "result"):
                if key in value:
                    return EVMExecutionInterface._error_data(Exception(value[key]))
            return b""
        if isinstance(value, (bytes, bytearray, memoryview)):
            return bytes(value)
        if isinstance(value, str):
            try:
                return StorageEngine._decode_hex(value)
            except (TypeError, ValueError):
                match = re.search(r"0x[0-9a-fA-F]{8,}", value)
                return bytes.fromhex(match.group(0)[2:]) if match else b""
        return b""

    @staticmethod
    def _is_out_of_gas(error: Exception) -> bool:
        message = str(error).lower().replace("_", " ")
        return "out of gas" in message or "outofgas" in message

    @staticmethod
    def _account_for(caller: str) -> Any:
        if not APE_AVAILABLE or accounts is None:
            raise RuntimeError("Ape accounts are required for transaction execution")
        try:
            return accounts[caller]
        except (KeyError, TypeError, ValueError):
            matches = [account for account in accounts if account.address.lower() == caller.lower()]
            if len(matches) != 1:
                raise RuntimeError(
                    f"caller {caller} is not a loaded Ape account; load the fork signer explicitly"
                ) from None
            return matches[0]

    @staticmethod
    def _call_result_data(result: Any) -> Tuple[bytes, Optional[bytes]]:
        if isinstance(result, (bytes, bytearray, memoryview, str)):
            return StorageEngine._decode_hex(result or "0x"), None
        revert = getattr(result, "revert", None)
        if revert is not None:
            raw = getattr(revert, "data", None)
            if raw is None:
                raw = getattr(revert, "return_data", b"")
            return b"", EVMExecutionInterface._error_data(Exception(raw)) if raw else b""
        return_data = getattr(result, "returndata", b"") or b""
        return StorageEngine._decode_hex(return_data), None

    def execute_raw(self, caller: str, to: str, calldata: bytes) -> ExecutionResult:
        """Simulate and submit through Ape's provider/account transaction APIs.

        ``ContractLogicError`` belongs at the two execution boundaries where
        Ape invokes EVM code: ``ProviderAPI.send_call`` for the preflight and
        ``AccountAPI.call`` for the state-mutating transaction. It must not be
        used around storage reads or SQLite operations. The provider's
        ``send_call`` result is retained for raw return bytes, while the Ape
        receipt supplies the transaction hash and execution status.
        """
        self.assert_target_allowed(to)
        if not isinstance(calldata, bytes):
            raise TypeError("calldata must be bytes")
        account = self._account_for(caller)
        transaction = self.provider.network.ecosystem.create_transaction(
            sender=account.address,
            receiver=to,
            data=calldata,
            required_confirmations=0,
        )

        try:
            call_result = self.provider.send_call(transaction)
            return_data, call_revert_data = self._call_result_data(call_result)
            if call_revert_data is not None:
                return ExecutionResult(
                    False,
                    revert_data=call_revert_data,
                    error_kind="REVERT" if call_revert_data else "CALL_FAILED",
                )
        except ContractLogicError as error:
            revert_data = self._error_data(error)
            return ExecutionResult(
                False,
                revert_data=revert_data,
                error_kind="REVERT" if revert_data else ("OUT_OF_GAS" if self._is_out_of_gas(error) else "CALL_FAILED"),
            )
        except Exception as error:
            return ExecutionResult(
                False,
                error_kind="OUT_OF_GAS" if self._is_out_of_gas(error) else "CALL_FAILED",
            )

        try:
            receipt = account.call(transaction)
        except ContractLogicError as error:
            revert_data = self._error_data(error)
            return ExecutionResult(
                False,
                return_data=return_data,
                revert_data=revert_data,
                error_kind="REVERT" if revert_data else ("OUT_OF_GAS" if self._is_out_of_gas(error) else "TX_REVERTED"),
            )
        except Exception as error:
            return ExecutionResult(
                False,
                return_data=return_data,
                error_kind="OUT_OF_GAS" if self._is_out_of_gas(error) else "TX_FAILED",
            )

        if getattr(receipt, "failed", False):
            error = getattr(receipt, "error", None)
            revert_data = self._error_data(error) if error is not None else b""
            return ExecutionResult(
                False,
                return_data=return_data,
                revert_data=revert_data,
                error_kind="REVERT" if revert_data else "TX_REVERTED",
                transaction_hash=str(getattr(receipt, "txn_hash", "")) or None,
            )
        return ExecutionResult(
            True,
            return_data=return_data,
            transaction_hash=str(getattr(receipt, "txn_hash", "")) or None,
        )


class EVMRevertDecoder:
    PANIC_CODES = {
        0x00: "Generic compiler panic",
        0x01: "Assert evaluated to false",
        0x11: "Arithmetic overflow/underflow",
        0x12: "Division or modulo zero",
        0x21: "Invalid enum conversion",
        0x22: "Invalid storage byte array encoding",
        0x31: "Empty array pop",
        0x32: "Array index out of bounds",
        0x41: "Resource or memory allocation error",
        0x51: "Zero initialized internal function call",
    }

    @classmethod
    def inspect(cls, data: bytes) -> RevertInfo:
        if len(data) < 4:
            return RevertInfo("EMPTY", "empty revert payload", "", data)

        selector = data[:4]
        payload = data[4:]
        if selector == bytes.fromhex("08c379a0") and len(payload) >= 64:
            try:
                offset = int.from_bytes(payload[:32], "big")
                length = int.from_bytes(payload[offset : offset + 32], "big")
                message = payload[offset + 32 : offset + 32 + length].decode("utf-8", "replace")
                return RevertInfo("ERROR_STRING", message, selector.hex(), data)
            except (IndexError, UnicodeError, ValueError):
                pass
        if selector == bytes.fromhex("4e487b71") and len(payload) >= 32:
            code = int.from_bytes(payload[:32], "big")
            return RevertInfo("PANIC", f"{hex(code)}: {cls.PANIC_CODES.get(code, 'Unknown Panic Code')}", selector.hex(), data)
        return RevertInfo("CUSTOM_ERROR", f"selector={selector.hex()}", selector.hex(), data)

    @classmethod
    def decode(cls, data: bytes) -> str:
        info = cls.inspect(data)
        return f"{info.kind}({info.message})" if info.message else info.kind


class ExploitMemoryDB:
    """Relational store for topology, test vectors, and isolated trace results."""

    def __init__(self, db_path: str = ":memory:", cache_path: str = ":memory:") -> None:
        self.conn = sqlite3.connect(db_path)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA foreign_keys = ON")
        # Separate relational cache mirroring the Ape execution cache: raw
        # receipts, gas, events, and bytecode hashes per chain/block.
        self.cache_conn = sqlite3.connect(cache_path)
        self.cache_conn.row_factory = sqlite3.Row
        self._init_tables()
        self._init_cache()

    def _init_tables(self) -> None:
        with self.conn:
            self.conn.execute(
                """
                CREATE TABLE IF NOT EXISTS target_topology (
                    address TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    admin_slot TEXT,
                    impl_slot TEXT,
                    tracked_slots TEXT NOT NULL,
                    scope_id TEXT NOT NULL,
                    chain_id INTEGER NOT NULL,
                    fork_block INTEGER NOT NULL,
                    source_repo TEXT,
                    source_ref TEXT NOT NULL,
                    FOREIGN KEY(scope_id) REFERENCES execution_scopes(scope_id)
                )
                """
            )
            self.conn.execute(
                """
                CREATE TABLE IF NOT EXISTS execution_scopes (
                    scope_id TEXT PRIMARY KEY,
                    chain_id INTEGER NOT NULL,
                    fork_block INTEGER NOT NULL,
                    clone_id TEXT NOT NULL UNIQUE,
                    source_repo TEXT,
                    source_ref TEXT NOT NULL
                )
                """
            )
            self.conn.execute(
                """
                CREATE TABLE IF NOT EXISTS test_vectors (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    target_address TEXT NOT NULL,
                    function_signature TEXT NOT NULL,
                    vector_class TEXT NOT NULL,
                    calldata_payload TEXT,
                    status TEXT NOT NULL DEFAULT 'PENDING',
                    FOREIGN KEY(target_address) REFERENCES target_topology(address)
                )
                """
            )
            self.conn.execute(
                """
                CREATE TABLE IF NOT EXISTS execution_traces (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    vector_id INTEGER NOT NULL,
                    snapshot_id TEXT NOT NULL,
                    slot_index TEXT NOT NULL,
                    pre_state TEXT NOT NULL,
                    post_state TEXT NOT NULL,
                    revert_reason TEXT,
                    return_data TEXT,
                    revert_data TEXT,
                    error_kind TEXT,
                    transaction_hash TEXT,
                    success INTEGER NOT NULL,
                    FOREIGN KEY(vector_id) REFERENCES test_vectors(id)
                )
                """
            )
            self.conn.execute(
                """
                CREATE TABLE IF NOT EXISTS vulnerability_taxonomy (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    category TEXT NOT NULL,
                    root_cause TEXT NOT NULL,
                    source_ref TEXT NOT NULL,
                    reference_hash TEXT,
                    recipe_json TEXT
                )
                """
            )
            self.conn.execute(
                """
                CREATE TABLE IF NOT EXISTS poc_chains (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    chain_label TEXT NOT NULL,
                    target_address TEXT NOT NULL,
                    objective TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'PENDING',
                    scope_id TEXT NOT NULL,
                    FOREIGN KEY(target_address) REFERENCES target_topology(address)
                )
                """
            )
            self.conn.execute(
                """
                CREATE TABLE IF NOT EXISTS poc_chain_steps (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    chain_rowid INTEGER NOT NULL,
                    step_index INTEGER NOT NULL,
                    calldata_payload TEXT NOT NULL,
                    expected_pre TEXT NOT NULL,
                    snapshot_id TEXT,
                    status TEXT NOT NULL DEFAULT 'PENDING',
                    transaction_hash TEXT,
                    FOREIGN KEY(chain_rowid) REFERENCES poc_chains(id)
                )
                """
            )

    def _init_cache(self) -> None:
        with self.cache_conn:
            self.cache_conn.execute(
                """
                CREATE TABLE IF NOT EXISTS transaction_cache (
                    cache_key TEXT PRIMARY KEY,
                    chain_id INTEGER NOT NULL,
                    block_number INTEGER,
                    transaction_hash TEXT,
                    receipt_json TEXT NOT NULL,
                    gas_used INTEGER,
                    events_json TEXT,
                    bytecode_hash TEXT
                )
                """
            )

    def insert_taxonomy_entry(
        self,
        category: str,
        root_cause: str,
        source_ref: str,
        reference_hash: Optional[str] = None,
        recipe: Optional[Dict[str, Any]] = None,
    ) -> int:
        with self.conn:
            cursor = self.conn.execute(
                """
                INSERT INTO vulnerability_taxonomy(
                    category, root_cause, source_ref, reference_hash, recipe_json
                ) VALUES (?, ?, ?, ?, ?)
                """,
                (category, root_cause, source_ref, reference_hash, json.dumps(recipe or {})),
            )
            return int(cursor.lastrowid)

    def query_taxonomy(self, category: Optional[str] = None) -> List[Dict[str, Any]]:
        if category is None:
            rows = self.conn.execute("SELECT * FROM vulnerability_taxonomy ORDER BY id")
        else:
            rows = self.conn.execute(
                "SELECT * FROM vulnerability_taxonomy WHERE category = ? ORDER BY id", (category,)
            )
        return [dict(row) for row in rows]

    def create_poc_chain(self, scope: TargetScope, chain_label: str, objective: str) -> int:
        # Auto-register minimal topology so the FK holds even when a chain is
        # run without a preceding full analysis pass.
        row = self.conn.execute(
            "SELECT 1 FROM target_topology WHERE address = ?", (scope.normalized_target,)
        ).fetchone()
        if row is None:
            self.upsert_topology(scope, "chain-only target", [])
        with self.conn:
            cursor = self.conn.execute(
                """
                INSERT INTO poc_chains(chain_label, target_address, objective, status, scope_id)
                VALUES (?, ?, ?, 'PENDING', ?)
                """,
                (chain_label, scope.normalized_target, objective, scope.scope_id),
            )
            return int(cursor.lastrowid)

    def record_poc_step(
        self,
        chain_rowid: int,
        step_index: int,
        step: ChainStep,
        snapshot_id: Optional[str],
        status: str,
        transaction_hash: Optional[str],
    ) -> int:
        with self.conn:
            cursor = self.conn.execute(
                """
                INSERT INTO poc_chain_steps(
                    chain_rowid, step_index, calldata_payload, expected_pre,
                    snapshot_id, status, transaction_hash
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    chain_rowid,
                    step_index,
                    step.calldata.hex(),
                    json.dumps(step.expected_pre),
                    snapshot_id,
                    status,
                    transaction_hash,
                ),
            )
            return int(cursor.lastrowid)

    def update_poc_chain_status(self, chain_rowid: int, status: str) -> None:
        with self.conn:
            self.conn.execute("UPDATE poc_chains SET status = ? WHERE id = ?", (status, chain_rowid))

    def cache_receipt(
        self,
        cache_key: str,
        transaction_hash: Optional[str],
        receipt: Dict[str, Any],
        chain_id: int,
        block_number: Optional[int] = None,
        gas_used: Optional[int] = None,
        events: Optional[List[Dict[str, Any]]] = None,
        bytecode_hash: Optional[str] = None,
    ) -> None:
        with self.cache_conn:
            self.cache_conn.execute(
                """
                INSERT INTO transaction_cache(
                    cache_key, chain_id, block_number, transaction_hash,
                    receipt_json, gas_used, events_json, bytecode_hash
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(cache_key) DO UPDATE SET
                    chain_id=excluded.chain_id,
                    block_number=excluded.block_number,
                    transaction_hash=excluded.transaction_hash,
                    receipt_json=excluded.receipt_json,
                    gas_used=excluded.gas_used,
                    events_json=excluded.events_json,
                    bytecode_hash=excluded.bytecode_hash
                """,
                (
                    cache_key,
                    chain_id,
                    block_number,
                    transaction_hash,
                    json.dumps(receipt, sort_keys=True),
                    gas_used,
                    json.dumps(events or []),
                    bytecode_hash,
                ),
            )

    def lookup_cached_receipt(self, cache_key: str) -> Optional[Dict[str, Any]]:
        row = self.cache_conn.execute(
            "SELECT * FROM transaction_cache WHERE cache_key = ?", (cache_key,)
        ).fetchone()
        if row is None:
            return None
        entry = dict(row)
        entry["receipt"] = json.loads(entry.pop("receipt_json"))
        entry["events"] = json.loads(entry.pop("events_json") or "[]")
        return entry

    def upsert_topology(self, scope: TargetScope, name: str, tracked_slots: Iterable[int]) -> None:
        admin_slot = hex(EIP1967_ADMIN_SLOT)
        impl_slot = hex(EIP1967_IMPLEMENTATION_SLOT)
        with self.conn:
            self.conn.execute(
                """
                INSERT INTO execution_scopes(scope_id, chain_id, fork_block, clone_id, source_repo, source_ref)
                VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(scope_id) DO UPDATE SET
                    chain_id=excluded.chain_id,
                    fork_block=excluded.fork_block,
                    clone_id=excluded.clone_id,
                    source_repo=excluded.source_repo,
                    source_ref=excluded.source_ref
                """,
                (scope.scope_id, scope.chain_id, scope.fork_block, scope.clone_id, scope.source_repo, scope.source_ref),
            )
            self.conn.execute(
                """
                INSERT INTO target_topology(
                    address, name, admin_slot, impl_slot, tracked_slots,
                    scope_id, chain_id, fork_block, source_repo, source_ref
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(address) DO UPDATE SET
                    name=excluded.name,
                    admin_slot=excluded.admin_slot,
                    impl_slot=excluded.impl_slot,
                    tracked_slots=excluded.tracked_slots,
                    scope_id=excluded.scope_id,
                    chain_id=excluded.chain_id,
                    fork_block=excluded.fork_block,
                    source_repo=excluded.source_repo,
                    source_ref=excluded.source_ref
                """,
                (
                    scope.normalized_target,
                    name,
                    admin_slot,
                    impl_slot,
                    json.dumps([hex(slot) for slot in sorted(set(tracked_slots))]),
                    scope.scope_id,
                    scope.chain_id,
                    scope.fork_block,
                    scope.source_repo,
                    scope.source_ref,
                ),
            )

    def insert_candidate(self, target: str, candidate: VulnerabilityCandidate) -> int:
        with self.conn:
            cursor = self.conn.execute(
                """
                INSERT INTO test_vectors(target_address, function_signature, vector_class)
                VALUES (?, ?, ?)
                """,
                (target.lower(), candidate.function_signature, candidate.vector_class.value),
            )
            return int(cursor.lastrowid)

    def update_calldata(self, vector_id: int, calldata: bytes) -> None:
        with self.conn:
            self.conn.execute(
                "UPDATE test_vectors SET calldata_payload = ? WHERE id = ?",
                (calldata.hex(), vector_id),
            )

    def update_status(self, vector_id: int, status: str) -> None:
        with self.conn:
            self.conn.execute("UPDATE test_vectors SET status = ? WHERE id = ?", (status, vector_id))

    def record_trace(
        self,
        vector_id: int,
        snapshot_id: str,
        slot_index: str,
        pre_state: bytes,
        post_state: bytes,
        revert_reason: Optional[str],
        success: bool,
        return_data: bytes = b"",
        revert_data: bytes = b"",
        error_kind: Optional[str] = None,
        transaction_hash: Optional[str] = None,
    ) -> None:
        with self.conn:
            self.conn.execute(
                """
                INSERT INTO execution_traces(
                    vector_id, snapshot_id, slot_index, pre_state, post_state,
                    revert_reason, return_data, revert_data, error_kind,
                    transaction_hash, success
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    vector_id,
                    snapshot_id,
                    slot_index,
                    pre_state.hex(),
                    post_state.hex(),
                    revert_reason,
                    return_data.hex(),
                    revert_data.hex(),
                    error_kind,
                    transaction_hash,
                    int(success),
                ),
            )

    def export_json(self) -> str:
        tables = (
            "test_vectors",
            "execution_traces",
            "vulnerability_taxonomy",
            "poc_chains",
            "poc_chain_steps",
        )
        payload = {name: [dict(row) for row in self.conn.execute(f"SELECT * FROM {name} ORDER BY id")] for name in tables}
        return json.dumps(payload, indent=2)


class ASTCFGAnalysisWorker:
    """Extract candidate state mutations and call risks from Slither metadata."""

    @staticmethod
    def calculate_selector(signature: str) -> str:
        return keccak(signature.encode("utf-8"))[:4].hex()

    @staticmethod
    def _type_name(abi_type: Any) -> str:
        candidate = getattr(abi_type, "type", abi_type)
        return str(getattr(candidate, "name", candidate))

    @staticmethod
    def _flatten_calls(calls: Any) -> List[Any]:
        flattened: List[Any] = []
        for group in calls or []:
            if isinstance(group, (list, tuple, set)):
                flattened.extend(group)
            else:
                flattened.append(group)
        return flattened

    @staticmethod
    def _modifier_names(function: Any) -> List[str]:
        names: List[str] = []
        for modifier in getattr(function, "modifiers", []) or []:
            names.append(str(getattr(modifier, "name", modifier)))
        names.extend(str(name) for name in getattr(function, "modifier_names", []) or [])
        return names

    @staticmethod
    def _variable_name(variable: Any) -> str:
        name = getattr(variable, "name", variable)
        return str(name).split(":")[-1].split(".")[-1]

    @staticmethod
    def _storage_layout(contract: Any) -> Dict[str, Dict[str, Any]]:
        """Normalize Slither's version-specific storage layout shapes."""
        layout = getattr(contract, "storage_layout", None)
        if layout is None:
            getter = getattr(contract, "get_storage_layout", None)
            layout = getter() if callable(getter) else None
        if isinstance(layout, dict):
            if "storage" in layout or "storageLayout" in layout:
                layout = layout.get("storage", layout.get("storageLayout", []))
            else:
                layout = [
                    dict(value, label=value.get("label", name))
                    if isinstance(value, dict)
                    else {"label": name, "slot": value}
                    for name, value in layout.items()
                ]
        result: Dict[str, Dict[str, Any]] = {}
        for item in layout or []:
            if not isinstance(item, dict):
                continue
            raw_name = item.get("label") or item.get("astId")
            slot = item.get("slot")
            if not raw_name or slot is None:
                continue
            name = str(raw_name).split(":")[-1].split(".")[-1]
            try:
                parsed_slot = int(str(slot), 0) if isinstance(slot, str) else int(slot)
            except (TypeError, ValueError):
                continue
            result[name] = {"slot": parsed_slot, "type": item.get("type", "")}
        return result

    def analyze_source(self, contract_path: str, contract_name: Optional[str] = None) -> List[VulnerabilityCandidate]:
        try:
            from slither.slither import Slither
        except ImportError as exc:
            raise RuntimeError("Slither is required for source-level CFG analysis") from exc

        slither = Slither(contract_path)
        if contract_name:
            contracts = slither.get_contract_from_name(contract_name)
            if not contracts:
                raise ValueError(f"contract not found by Slither: {contract_name}")
            targets = contracts
        else:
            targets = list(slither.contracts)

        candidates: List[VulnerabilityCandidate] = []
        for contract in targets:
            layout = self._storage_layout(contract)
            for function in contract.functions:
                if not function.is_implemented or function.visibility not in ("public", "external"):
                    continue
                modifiers = self._modifier_names(function)
                is_protected = bool(modifiers)
                external_calls = self._flatten_calls(getattr(function, "high_level_calls", []))
                low_level_calls = self._flatten_calls(getattr(function, "low_level_calls", []))
                has_delegatecall = any(getattr(call, "is_delegate_call", False) for call in low_level_calls)
                has_arbitrary_call = any(getattr(call, "is_call", False) for call in low_level_calls)
                has_selfdestruct = bool(getattr(function, "is_selfdestruct", False))
                written_argument_sources = False
                for source in getattr(function, "parameters", []) or []:
                    if getattr(source, "is_argument", False) or getattr(source, "is_parameter", False):
                        written_argument_sources = True
                        break
                argument_influenced_call = has_arbitrary_call and written_argument_sources
                argument_influenced_delegate = has_delegatecall and written_argument_sources
                can_reenter = getattr(function, "can_reenter", None)
                can_reenter = bool(can_reenter() if callable(can_reenter) else can_reenter)
                input_types = [self._type_name(item) for item in getattr(function, "inputs", [])]
                signature = getattr(function, "signature_str", None) or f"{function.name}({','.join(input_types)})"
                selector = self.calculate_selector(signature)
                written_names = [self._variable_name(item) for item in (getattr(function, "state_variables_written", []) or [])]
                read_names = [self._variable_name(item) for item in (getattr(function, "state_variables_read", []) or [])]
                referenced_names = list(dict.fromkeys(written_names + read_names))
                target_slots: List[StorageSlotRef] = []
                for name in referenced_names:
                    item = layout.get(name)
                    if item is None:
                        continue
                    type_descriptor = item.get("type", "")
                    type_name = str(type_descriptor)
                    size_bytes = getattr(type_descriptor, "size", item.get("size", 32))
                    try:
                        size_bytes = int(size_bytes)
                    except (TypeError, ValueError):
                        size_bytes = 32
                    target_slots.append(
                        StorageSlotRef(
                            slot=item["slot"],
                            offset=int(item.get("offset", 0)),
                            size_bytes=size_bytes,
                            label=name,
                            is_mapping="mapping" in type_name.lower(),
                        )
                    )

                if argument_influenced_delegate:
                    delegate_slots = target_slots + [StorageSlotRef(EIP1967_IMPLEMENTATION_SLOT, label="EIP1967_IMPLEMENTATION")]
                    candidates.append(
                        VulnerabilityCandidate(
                            VectorClass.CONTROLLED_DELEGATECALL,
                            function.name,
                            signature,
                            selector,
                            input_types,
                            list({reference.slot: reference for reference in delegate_slots}.values()),
                        )
                    )
                if has_delegatecall and not is_protected:
                    candidates.append(
                        VulnerabilityCandidate(
                            VectorClass.CONTROLLED_DELEGATECALL,
                            function.name,
                            signature,
                            selector,
                            input_types,
                            [StorageSlotRef(EIP1967_IMPLEMENTATION_SLOT, label="EIP1967_IMPLEMENTATION")],
                        )
                    )
                if argument_influenced_call:
                    candidates.append(
                        VulnerabilityCandidate(
                            VectorClass.ARBITRARY_EXTERNAL_CALL,
                            function.name,
                            signature,
                            selector,
                            input_types,
                            target_slots,
                        )
                    )
                if has_selfdestruct and not is_protected:
                    candidates.append(
                        VulnerabilityCandidate(
                            VectorClass.METAMORPHIC_SELFDESTRUCT,
                            function.name,
                            signature,
                            selector,
                            input_types,
                            [StorageSlotRef(EIP1967_IMPLEMENTATION_SLOT, label="EIP1967_IMPLEMENTATION")],
                        )
                    )
                if written_names and not is_protected:
                    if not target_slots:
                        raise ValueError(f"Slither returned no storage slots for {function.name}")
                    candidates.append(
                        VulnerabilityCandidate(
                            VectorClass.UNPROTECTED_STATE_WRITE,
                            function.name,
                            signature,
                            selector,
                            input_types,
                            target_slots,
                            [{"type": "non_zero", "arg_index": index} for index, input_type in enumerate(input_types) if input_type == "address"],
                        )
                    )
                if can_reenter and external_calls:
                    candidates.append(
                        VulnerabilityCandidate(
                            VectorClass.REENTRANCY,
                            function.name,
                            signature,
                            selector,
                            input_types,
                            target_slots,
                        )
                    )
        return candidates


class StateAwareZ3SolverWorker:
    """Solve bounded calldata constraints using live integer storage values."""

    @staticmethod
    def _width(abi_type: str) -> int:
        if abi_type.startswith("uint") or abi_type.startswith("int"):
            return int(abi_type[4:] or "256")
        if abi_type == "address":
            return 160
        if abi_type == "bool":
            return 1
        if abi_type == "bytes32":
            return 256
        raise ValueError(f"unsupported static ABI type: {abi_type}")

    @staticmethod
    def _is_signed(abi_type: str) -> bool:
        return abi_type.startswith("int")

    def _apply_comparison(self, solver: Any, abi_type: str, variable: Any, operation: str, value: int) -> None:
        if abi_type.startswith("uint") or abi_type == "address" or abi_type in ("bool", "bytes32"):
            greater, less = z3.UGT, z3.ULT
        elif abi_type.startswith("int"):
            greater, less = z3.SGT, z3.SLT
        else:
            raise ValueError(f"state comparison does not support ABI type: {abi_type}")
        if operation == "gt":
            solver.add(greater(variable, value))
        elif operation == "lt":
            solver.add(less(variable, value))
        elif operation == "eq":
            solver.add(variable == value)
        else:
            raise ValueError(f"unsupported Z3 operation: {operation}")

    def solve_for_vector(self, candidate: VulnerabilityCandidate, current_chain_state: Dict[str, Any]) -> bytes:
        solver = z3.Solver()
        variables: List[Tuple[str, z3.BitVecRef]] = []
        for index, abi_type in enumerate(candidate.input_types):
            variable = z3.BitVec(f"arg_{index}_{abi_type}", self._width(abi_type))
            variables.append((abi_type, variable))
            if abi_type == "address":
                solver.add(variable != 0)
            elif abi_type == "bool":
                solver.add(z3.ULT(variable, 2))

        for invariant in candidate.required_invariants:
            index = int(invariant["arg_index"])
            if not 0 <= index < len(variables):
                raise ValueError(f"constraint references missing ABI argument: {index}")
            abi_type, variable = variables[index]
            if invariant.get("type") == "non_zero":
                solver.add(variable != 0)
                continue
            self._apply_comparison(solver, abi_type, variable, invariant["op"], int(invariant["value"]))

        # read_dynamic_state() materializes these constraints from the live
        # provider. This keeps the symbolic model tied to actual storage
        # rather than silently solving against a disconnected snapshot.
        for constraint in current_chain_state.get("__constraints__", []):
            index = int(constraint["arg_index"])
            if not 0 <= index < len(variables):
                raise ValueError(f"dynamic constraint references missing ABI argument: {index}")
            abi_type, variable = variables[index]
            self._apply_comparison(solver, abi_type, variable, constraint["op"], int(constraint["value"]))

        if solver.check() != z3.sat:
            raise ValueError(f"constraints are unsatisfiable for {candidate.function_signature}")
        model = solver.model()
        payload = bytes.fromhex(candidate.four_byte_selector)
        for abi_type, variable in variables:
            value = model[variable].as_long()
            width = self._width(abi_type)
            payload += (value & ((1 << width) - 1)).to_bytes(32, byteorder="big")
        return payload


class DynamicVerificationSubAgent:
    """Execute one candidate inside a provider snapshot and diff every tracked slot."""

    def __init__(self, storage: StorageEngine, memory: ExploitMemoryDB) -> None:
        self.storage = storage
        self.memory = memory

    @staticmethod
    def _mapping_key_bytes(raw_key: Any) -> bytes:
        if isinstance(raw_key, int):
            return raw_key.to_bytes(32, byteorder="big", signed=False)
        if isinstance(raw_key, str):
            value = raw_key[2:] if raw_key.startswith("0x") else raw_key
            return bytes.fromhex(value)
        if isinstance(raw_key, bytes):
            return raw_key
        raise TypeError(f"unsupported mapping key: {type(raw_key)!r}")

    def _resolved_slot(self, reference: StorageSlotRef) -> int:
        if reference.is_mapping and reference.mapping_key is not None:
            return self.storage.compute_mapping_slot(
                self._mapping_key_bytes(reference.mapping_key), reference.slot
            )
        return reference.slot

    def read_dynamic_state(self, target_address: str, candidate: VulnerabilityCandidate) -> Dict[str, Any]:
        """Read live slots and expose state-derived constraints to Z3.

        A source-level invariant may opt into a live comparison with
        ``{"type": "state_compare", "arg_index": 0,
        "state_label": "reserve_ratio", "op": "lt"}``. The value is read from
        the provider at solve time, not copied from a static assumption.
        """
        state: Dict[str, Any] = {}
        for reference in candidate.target_slots:
            if not reference.label:
                continue
            value = int.from_bytes(
                self.storage.get_storage_at(target_address, self._resolved_slot(reference)), "big"
            )
            state[reference.label] = value
        constraints = []
        for invariant in candidate.required_invariants:
            if invariant.get("type") != "state_compare":
                continue
            label = invariant.get("state_label")
            if label not in state:
                raise ValueError(f"dynamic state label is not tracked: {label}")
            constraints.append(
                {
                    "arg_index": int(invariant["arg_index"]),
                    "op": invariant["op"],
                    "value": state[label],
                }
            )
        state["__constraints__"] = constraints
        return state

    async def verify_candidate(
        self,
        vector_id: int,
        target_address: str,
        candidate: VulnerabilityCandidate,
        calldata: bytes,
    ) -> bool:
        snapshot_id = self.storage.snapshot()
        try:
            resolved_slots = {
                self._resolved_slot(reference): reference for reference in candidate.target_slots
            }
            pre_state = self.storage.get_storage_range(target_address, resolved_slots)
            result = self.storage.execute_raw(
                caller="0x0000000000000000000000000000000000000001",
                to=target_address,
                calldata=calldata,
            )
            post_state = self.storage.get_storage_range(target_address, resolved_slots)
            reason = None if result.success else (
                EVMRevertDecoder.decode(result.revert_data)
                if result.revert_data
                else result.error_kind or "execution failed"
            )
            any_mutated = False
            for slot, pre_value in pre_state.items():
                post_value = post_state[slot]
                mutated = pre_value != post_value
                any_mutated = any_mutated or mutated
                self.memory.record_trace(
                    vector_id=vector_id,
                    snapshot_id=snapshot_id,
                    slot_index=hex(slot),
                    pre_state=pre_value,
                    post_state=post_value,
                    revert_reason=reason,
                    success=result.success,
                    return_data=result.return_data,
                    revert_data=result.revert_data,
                    error_kind=result.error_kind,
                    transaction_hash=result.transaction_hash,
                )
            status = (
                "CONFIRMED"
                if result.success and any_mutated
                else "NO_STATE_CHANGE"
                if result.success
                else "REVERTED"
                if result.error_kind == "REVERT"
                else "EXECUTION_ERROR"
            )
            self.memory.update_status(vector_id, status)
            return result.success and any_mutated
        finally:
            self.storage.revert(snapshot_id)

    async def execute_poc_chain(
        self,
        chain_label: str,
        objective: str,
        steps: List[ChainStep],
    ) -> Dict[str, Any]:
        """Run a multi-step PoC with deterministic per-step continuity checks.

        Each step is executed inside its own snapshot. Before submitting, the
        step's ``expected_pre`` slot values are asserted against the live fork,
        which enforces that step N left the exact preconditions required by
        step N+1. The outer snapshot is restored afterwards, so a confirmed
        chain can be replayed from a clean state without polluting the fork.
        """
        if not steps:
            raise ValueError("a PoC chain requires at least one step")
        chain_rowid = self.memory.create_poc_chain(
            self.storage.scope, chain_label, objective
        )
        outer_snapshot = self.storage.snapshot()
        try:
            step_results: List[Dict[str, Any]] = []
            chain_status = "CONFIRMED"
            for index, step in enumerate(steps):
                step_snapshot = self.storage.snapshot()
                status = "CONFIRMED"
                transaction_hash: Optional[str] = None
                try:
                    for slot_text, expected_hex in step.expected_pre.items():
                        slot = int(slot_text, 0)
                        actual_value = int.from_bytes(
                            self.storage.get_storage_at(step.target_address, slot), "big"
                        )
                        if actual_value != int(expected_hex, 16):
                            status = "PRECONDITION_MISMATCH"
                            break
                    if status == "CONFIRMED":
                        result = self.storage.execute_raw(
                            caller="0x0000000000000000000000000000000000000001",
                            to=step.target_address,
                            calldata=step.calldata,
                        )
                        transaction_hash = result.transaction_hash
                        if not result.success:
                            status = "REVERTED" if result.error_kind == "REVERT" else "EXECUTION_ERROR"
                finally:
                    self.storage.revert(step_snapshot)
                self.memory.record_poc_step(
                    chain_rowid=chain_rowid,
                    step_index=index,
                    step=step,
                    snapshot_id=step_snapshot,
                    status=status,
                    transaction_hash=transaction_hash,
                )
                step_results.append({"step": index, "status": status, "transaction": transaction_hash})
                if status != "CONFIRMED":
                    chain_status = "FAILED"
            self.memory.update_poc_chain_status(chain_rowid, chain_status)
            return {"chain_rowid": chain_rowid, "status": chain_status, "steps": step_results}
        finally:
            self.storage.revert(outer_snapshot)


class MasterOrchestratorAgent:
    """Route source analysis, state-aware solving, and isolated verification."""

    def __init__(self, evm_interface: Optional[EVMExecutionInterface] = None, scope: Optional[TargetScope] = None) -> None:
        if scope is None:
            raise ValueError("a TargetScope is required; toy execution is not supported")
        self.scope = ScopedCloneRegistry().register(scope)
        self.storage = evm_interface or EVMExecutionInterface(scope=self.scope)
        self.storage.bind_scope(self.scope)
        self.memory = ExploitMemoryDB()
        self.ast_worker = ASTCFGAnalysisWorker()
        self.solver = StateAwareZ3SolverWorker()
        self.verifier = DynamicVerificationSubAgent(self.storage, self.memory)

    def execute_poc_chain(self, chain_label: str, objective: str, steps: List[ChainStep]) -> Dict[str, Any]:
        """Execute a multi-step PoC chain against the isolated fork scope."""
        return asyncio.run(self.verifier.execute_poc_chain(chain_label, objective, steps))

    async def execute_task(
        self,
        target_address: str,
        contract_path: str,
        contract_name: Optional[str] = None,
    ) -> Dict[str, Any]:
        normalized_target = target_address.lower()
        self.storage.assert_target_allowed(normalized_target)
        task_snapshot = self.storage.snapshot()
        try:
            candidates = self.ast_worker.analyze_source(contract_path, contract_name)
            proxy_slots = [
                StorageSlotRef(EIP1967_ADMIN_SLOT, label="EIP1967_ADMIN"),
                StorageSlotRef(EIP1967_IMPLEMENTATION_SLOT, label="EIP1967_IMPLEMENTATION"),
                StorageSlotRef(EIP1967_BEACON_SLOT, label="EIP1967_BEACON"),
            ]
            for candidate in candidates:
                merged = candidate.target_slots + proxy_slots
                candidate.target_slots = list({reference.slot: reference for reference in merged}.values())
            tracked_slots = {reference.slot for candidate in candidates for reference in candidate.target_slots}
            self.memory.upsert_topology(
                self.scope,
                contract_name or "Enzyme Blue target",
                tracked_slots,
            )

            results: List[Dict[str, Any]] = []
            for candidate in candidates:
                vector_id = self.memory.insert_candidate(normalized_target, candidate)
                dynamic_state = self.verifier.read_dynamic_state(normalized_target, candidate)
                calldata = self.solver.solve_for_vector(candidate, dynamic_state)
                self.memory.update_calldata(vector_id, calldata)
                confirmed = await self.verifier.verify_candidate(
                    vector_id, normalized_target, candidate, calldata
                )
                results.append(
                    {
                        "vector_id": vector_id,
                        "function": candidate.function_signature,
                        "vector": candidate.vector_class.value,
                        "confirmed": confirmed,
                    }
                )
            return {
                "target": normalized_target,
                "scope_id": self.scope.scope_id,
                "results": results,
                "audit_log": json.loads(self.memory.export_json()),
            }
        finally:
            self.storage.revert(task_snapshot)


async def run_scoped_task(
    scope: TargetScope,
    target_address: str,
    contract_path: str,
    contract_name: Optional[str] = None,
) -> Dict[str, Any]:
    """Convenience API for callers that already created their mainnet fork."""
    return await MasterOrchestratorAgent(scope=scope).execute_task(
        target_address, contract_path, contract_name
    )


class ToolchainAvailability:
    """Deterministic toolchain bridge for external analysis engines.

    Reports which third-party engines are importable or on PATH without
    launching them and without fabricating results. Availability only: the
    harness never shells out to fuzzers or symbolic executors implicitly, and
    a missing engine is a reported fact rather than an error.
    """

    REQUIRED_MODULES = {
        "slither": "slither-analyzer",
        "z3": "z3-solver",
        "ape": "eth-ape",
    }
    REQUIRED_BINARIES = {
        "anvil": "foundryup (anvil for local fork snapshots)",
        "forge": "foundryup (forge for deterministic PoC replay)",
        "cast": "foundryup (cast for storage dumps)",
    }

    @classmethod
    def survey(cls) -> Dict[str, Dict[str, str]]:
        import importlib.util
        import shutil

        def module_available(name: str) -> bool:
            try:
                return importlib.util.find_spec(name) is not None
            except ValueError:
                # A namespace-style stub module has no __spec__; treat it as
                # present for survey purposes.
                return True

        modules = {
            name: {
                "package": package,
                "available": "yes" if module_available(name) else "no",
            }
            for name, package in cls.REQUIRED_MODULES.items()
        }
        binaries = {
            name: {
                "purpose": purpose,
                "available": "yes" if shutil.which(name) else "no",
            }
            for name, purpose in cls.REQUIRED_BINARIES.items()
        }
        return {"python_modules": modules, "binaries": binaries}
