import asyncio
import sys
import types
import unittest


# Keep these tests runnable in the minimal harness environment. Production uses
# the real packages declared in requirements.txt.
if "z3" not in sys.modules:
    try:
        import z3  # noqa: F401
    except ModuleNotFoundError:
        z3 = types.ModuleType("z3")
        z3.BitVecRef = object
        sys.modules["z3"] = z3
if "eth_hash.auto" not in sys.modules:
    try:
        from eth_hash.auto import keccak  # noqa: F401
    except ModuleNotFoundError:
        eth_hash = types.ModuleType("eth_hash")
        eth_hash_auto = types.ModuleType("eth_hash.auto")
        eth_hash_auto.keccak = lambda data: b"\x01" * 32
        eth_hash.auto = eth_hash_auto
        sys.modules["eth_hash"] = eth_hash
        sys.modules["eth_hash.auto"] = eth_hash_auto

import unified_security_harness as harness  # noqa: E402
from unified_security_harness import (  # noqa: E402
    ChainStep,
    EVMExecutionInterface,
    ExploitMemoryDB,
    StorageSlotRef,
    TargetScope,
    VulnerabilityCandidate,
    VectorClass,
    DynamicVerificationSubAgent,
    ToolchainAvailability,
)


class FakeReceipt:
    failed = False
    txn_hash = "0xtx"


class FakeAccount:
    def __init__(self, provider, address="0x" + "22" * 20):
        self.address = address
        self.provider = provider

    def call(self, transaction):
        self.provider.calls.append(("account.call", transaction))
        if isinstance(transaction, dict) and transaction.get("sender") == self.address:
            self.provider.values[0] = int(9).to_bytes(32, "big")
        return FakeReceipt()


class FakeAccounts:
    def __init__(self, account):
        self.account = account

    def __getitem__(self, address):
        if address.lower() != self.account.address.lower():
            raise KeyError(address)
        return self.account

    def __iter__(self):
        # Expose both the loaded signer and the impersonated fallback caller
        # used by chain/vector execution on local providers.
        return iter((self.account, ImpersonatedCaller(self.account.provider)))


class ImpersonatedCaller(FakeAccount):
    """Local-fork impersonation handle for the deterministic default caller."""

    def __init__(self, provider):
        super().__init__(provider, address="0x0000000000000000000000000000000000000001")

    def call(self, transaction):
        self.provider.calls.append(("account.call", transaction))
        if isinstance(transaction, dict) and transaction.get("sender") == self.address:
            self.provider.values[0] = int(8).to_bytes(32, "big")
        return FakeReceipt()


class FakeProvider:
    def __init__(self):
        self.values = {0: int(7).to_bytes(32, "big")}
        self.snapshot_ids = iter((101, 102, 103, 104, 105, 106))
        self.snapshots = {}
        self.reverted = []
        self.calls = []
        self.network = types.SimpleNamespace(
            ecosystem=types.SimpleNamespace(create_transaction=lambda **kwargs: kwargs)
        )
        self.account = FakeAccount(self)
        self.call_error = None

    def send_call(self, transaction):
        self.calls.append(("send_call", transaction))
        if self.call_error is not None:
            raise self.call_error
        return b"\x01\x02\x03"

    def make_request(self, method, params):
        self.calls.append((method, params))
        if method == "evm_snapshot":
            snapshot_id = next(self.snapshot_ids)
            self.snapshots[snapshot_id] = dict(self.values)
            return snapshot_id
        if method == "evm_revert":
            snapshot_id = params[0]
            self.reverted.append(snapshot_id)
            if snapshot_id in self.snapshots:
                self.values = dict(self.snapshots[snapshot_id])
                del self.snapshots[snapshot_id]
            return True
        if method == "eth_getStorageAt":
            return self.values.get(int(params[1], 0), b"\x00" * 32)
        raise AssertionError(f"unexpected RPC method: {method}")


class HarnessProviderTests(unittest.TestCase):
    def setUp(self):
        self.scope = TargetScope.enzyme_blue(
            "scope-test", "0x" + "11" * 20, 123, "http://fake", "clone-test"
        )
        self.provider = FakeProvider()
        self.original_accounts = harness.accounts
        self.original_ape_available = harness.APE_AVAILABLE
        harness.accounts = FakeAccounts(self.provider.account)
        harness.APE_AVAILABLE = True
        self.engine = EVMExecutionInterface(provider=self.provider, scope=self.scope)

    def tearDown(self):
        harness.accounts = self.original_accounts
        harness.APE_AVAILABLE = self.original_ape_available

    def test_snapshot_preserves_raw_provider_id(self):
        snapshot = self.engine.snapshot()
        self.assertEqual(snapshot, "101")
        self.assertTrue(self.engine.revert(snapshot))
        self.assertEqual(self.provider.reverted, [101])

    def test_raw_execution_submits_transaction_after_call(self):
        result = self.engine.execute_raw(
            "0x" + "22" * 20, self.scope.target_address, b"\x01\x02\x03\x04"
        )
        self.assertTrue(result.success)
        self.assertEqual(result.return_data, b"\x01\x02\x03")
        self.assertEqual(result.transaction_hash, "0xtx")
        self.assertEqual(self.engine.get_storage_at(self.scope.target_address, 0)[-1], 9)
        methods = [method for method, _ in self.provider.calls]
        self.assertEqual(methods.index("send_call") + 1, methods.index("account.call"))

    def test_poc_chain_verifies_preconditions_and_rolls_back(self):
        steps = [
            ChainStep(
                target_address=self.scope.target_address,
                calldata=b"\xaa\xbb\xcc\xdd",
                expected_pre={"0x0": "0x" + int(7).to_bytes(32, "big").hex()},
                step_note="seed state",
            ),
            ChainStep(
                target_address=self.scope.target_address,
                calldata=b"\x11\x22\x33\x44",
                expected_pre={"0x0": "0x" + int(7).to_bytes(32, "big").hex()},
                step_note="exploit step",
            ),
        ]
        chain = self.engine.verifier if hasattr(self.engine, "verifier") else None
        verifier = chain or DynamicVerificationSubAgent(self.engine, ExploitMemoryDB())
        report = asyncio.run(
            verifier.execute_poc_chain("label", "objective", steps)
        )
        self.assertEqual(report["status"], "CONFIRMED")
        self.assertTrue(all(step["status"] == "CONFIRMED" for step in report["steps"]))

    def test_poc_chain_rejects_stale_precondition(self):
        step = ChainStep(
            target_address=self.scope.target_address,
            calldata=b"\xaa\xbb\xcc\xdd",
            expected_pre={"0x0": "0x" + int(99).to_bytes(32, "big").hex()},
        )
        verifier = DynamicVerificationSubAgent(self.engine, ExploitMemoryDB())
        report = asyncio.run(verifier.execute_poc_chain("label", "objective", [step]))
        self.assertEqual(report["status"], "FAILED")
        self.assertEqual(report["steps"][0]["status"], "PRECONDITION_MISMATCH")

    def test_transaction_cache_roundtrip(self):
        database = ExploitMemoryDB()
        database.cache_receipt(
            "key-1",
            "0xabc",
            {"status": 1},
            chain_id=1,
            block_number=42,
            gas_used=53000,
            events=[{"name": "Deposit"}],
            bytecode_hash="0xdeadbeef",
        )
        entry = database.lookup_cached_receipt("key-1")
        self.assertEqual(entry["receipt"]["status"], 1)
        self.assertEqual(entry["gas_used"], 53000)
        self.assertEqual(entry["events"][0]["name"], "Deposit")
        self.assertIsNone(database.lookup_cached_receipt("missing"))

    def test_taxonomy_query_and_chain_rows(self):
        database = ExploitMemoryDB()
        database.upsert_topology(self.scope, "EnzymeBlue", [0, 1])
        database.insert_taxonomy_entry(
            "READ_ONLY_REENTRANCY",
            "view used before state finalization",
            "post-mortem:0xabc",
            recipe={"steps": 2},
        )
        entries = database.query_taxonomy("READ_ONLY_REENTRANCY")
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0]["recipe_json"], '{"steps": 2}')
        chain_rowid = database.create_poc_chain(self.scope, "flash-manip", "drain invariant")
        self.memory = database
        step = ChainStep(self.scope.target_address, b"\x01\x02\x03\x04")
        database.record_poc_step(chain_rowid, 0, step, "snap-1", "CONFIRMED", "0xtx")
        export = database.export_json()
        self.assertIn("poc_chains", export)
        self.assertIn("vulnerability_taxonomy", export)

    def test_toolchain_availability_is_deterministic_survey(self):
        survey = ToolchainAvailability.survey()
        self.assertIn("z3", survey["python_modules"])
        self.assertIn("anvil", survey["binaries"])
        for module in survey["python_modules"].values():
            self.assertIn(module["available"], ("yes", "no"))

    def test_contract_logic_error_is_classified_at_call_boundary(self):
        error = harness.ContractLogicError("custom failure")
        error.data = bytes.fromhex("deadbeef")
        self.provider.call_error = error
        result = self.engine.execute_raw(
            "0x" + "22" * 20, self.scope.target_address, b"\x01\x02\x03\x04"
        )
        self.assertFalse(result.success)
        self.assertEqual(result.error_kind, "REVERT")
        self.assertEqual(result.revert_data, bytes.fromhex("deadbeef"))
        self.assertNotIn("account.call", [method for method, _ in self.provider.calls])

    def test_dynamic_state_creates_z3_constraints(self):
        candidate = VulnerabilityCandidate(
            VectorClass.ARITHMETIC_MANIPULATION,
            "setValue",
            "setValue(uint256)",
            "12345678",
            ["uint256"],
            [StorageSlotRef(0, label="reserve_ratio")],
            [{"type": "state_compare", "arg_index": 0, "state_label": "reserve_ratio", "op": "gt"}],
        )
        verifier = DynamicVerificationSubAgent(self.engine, ExploitMemoryDB())
        state = verifier.read_dynamic_state(self.scope.target_address, candidate)
        self.assertEqual(state["reserve_ratio"], 7)
        self.assertEqual(state["__constraints__"][0]["value"], 7)

    def test_database_keeps_scope_topology_and_raw_trace(self):
        database = ExploitMemoryDB()
        database.upsert_topology(self.scope, "EnzymeBlue", [0, 1])
        candidate = VulnerabilityCandidate(
            VectorClass.REENTRANCY, "f", "f()", "12345678", [], [StorageSlotRef(0)]
        )
        vector_id = database.insert_candidate(self.scope.target_address, candidate)
        database.record_trace(
            vector_id,
            "101",
            "0x0",
            b"\x00" * 32,
            b"\x01" * 32,
            None,
            True,
            return_data=b"\xaa",
            revert_data=b"",
            error_kind=None,
            transaction_hash="0xtx",
        )
        audit = database.conn.execute(
            "SELECT scope_id FROM target_topology WHERE address = ?", (self.scope.target_address,)
        ).fetchone()
        trace = database.conn.execute(
            "SELECT return_data, transaction_hash FROM execution_traces WHERE vector_id = ?",
            (vector_id,),
        ).fetchone()
        self.assertEqual(audit["scope_id"], "scope-test")
        self.assertEqual(tuple(trace), ("aa", "0xtx"))


if __name__ == "__main__":
    unittest.main()
