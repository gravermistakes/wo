# Enzyme Blue Security Harness — Engineering Handoff

## Status

The toy/mock target path has been removed. The harness is now a scoped, provider-backed Enzyme Blue analysis and verification tool. Forking is intentionally not performed by the module; the caller must create and connect the isolated Ape fork before invoking the pipeline.

Current workspace changes:

- `unified_security_harness.py` — provider-backed analysis, Z3 synthesis, Ape execution, snapshots, storage diffing, and SQLite persistence.
- `requirements.txt` — runtime dependencies.
- `test_unified_security_harness.py` — deterministic unit tests using test doubles only; no live fork.

## Runtime architecture

```text
MasterOrchestratorAgent
├── ASTCFGAnalysisWorker       Slither source metadata and storage layout
├── StateAwareZ3SolverWorker   ABI calldata synthesis and live-state constraints
├── ToolchainAvailability      deterministic external-engine survey (no shelling out)
└── DynamicVerificationSubAgent
    ├── EVMExecutionInterface  Ape provider/account execution
    ├── StorageEngine         snapshots, storage reads, mapping slots
    ├── PoC chain runner      multi-step preconditions + rollback
    └── ExploitMemoryDB       SQLite topology/vector/trace/taxonomy/cache persistence
```

All targets are bound to a `TargetScope` containing:

- Mainnet chain ID `1`
- Scoped target address
- Fork block
- RPC URL metadata
- Dedicated clone ID
- Enzyme source repository and source ref

Out-of-scope target access is rejected. There is no fallback target, mock storage, ABI keyword scanning, or demo entrypoint.

## Ape execution and `ContractLogicError`

`ContractLogicError` belongs at the EVM execution boundaries, not around storage reads or SQLite operations.

`EVMExecutionInterface.execute_raw()` now:

1. Resolves the explicitly loaded Ape account for the caller. It does not silently fall back to `accounts.test_accounts[0]`.
2. Creates an Ape ecosystem transaction containing the target, sender, and synthesized calldata.
3. Calls `ProviderAPI.send_call()` for preflight simulation and raw return/revert inspection.
4. Catches `ContractLogicError` from the preflight call and records raw revert data.
5. Calls `AccountAPI.call()` to submit the state-mutating transaction through Ape.
6. Catches `ContractLogicError` from the transaction call and classifies the failure.
7. Inspects the Ape receipt for failed status, error details, and transaction hash.

This is important: `Account.call()` in current Ape is a transaction submission API taking an Ape `TransactionAPI`; it is not the old `sender.call(to=..., data=...)` form. The provider `send_call()` path is used for simulation because it does not mutate fork state.

Storage inspection still uses the active Ape provider through `eth_getStorageAt`, `evm_snapshot`, and `evm_revert`. No direct live-mainnet transaction path is permitted without a caller-created isolated fork.

## Storage and verification behavior

Tracked slots include:

- Slither-derived state-variable slots
- Packed-slot offset/size metadata
- EIP-1967 admin, implementation, and beacon slots
- Mapping base slots
- Computed mapping slots when a concrete mapping key is available

Each vector runs inside its own snapshot and is rolled back in `finally`. The master task also has an outer snapshot. Pre/post slot values are recorded relationally, along with:

- Raw return data
- Raw revert data
- Decoded revert reason
- Error kind
- Transaction hash
- Success flag

Supported decoded failure classes include `Error(string)`, Solidity panic codes, and custom error selectors. Out-of-gas and provider failures remain distinct from ordinary reverts.

## Z3 and live state

The solver supports static ABI types:

- Signed and unsigned integers
- Addresses
- Booleans
- `bytes32`

It emits selector plus 32-byte ABI words and rejects unsatisfiable constraints rather than silently returning zeroed calldata.

Live storage is read before solving. A candidate can opt into a state-derived comparison using metadata such as:

```python
{
    "type": "state_compare",
    "arg_index": 0,
    "state_label": "reserve_ratio",
    "op": "gt",
}
```

`DynamicVerificationSubAgent.read_dynamic_state()` reads the referenced slot and emits a `__constraints__` entry containing the current provider value. The Z3 worker then applies that value as a signed or unsigned comparison against the corresponding argument.

Slither extraction is metadata-based rather than name-based. It records implemented public/external functions, storage reads/writes, modifiers, high-level calls, low-level calls, delegatecall usage, and reentrancy metadata.

## Specialized PoC-chain databases

`ExploitMemoryDB` implements the Ape-cache and taxonomy layers of the architecture:

- `transaction_cache` (separate `cache_conn`, Ape-cache analog): raw receipts keyed by `cache_key`, with chain id, block number, gas used, decoded events, and bytecode hash, so multi-step parameter continuity is verified against locally cached execution artifacts rather than remote queries.
- `vulnerability_taxonomy` (post-mortem/invariant analog): category, root cause, source reference, reference hash, and a JSON payload recipe; `query_taxonomy(category)` retrieves recipes for exploit generation.
- `poc_chains` and `poc_chain_steps`: label, objective, scope binding, per-step calldata, expected pre-state, snapshot id, status, and transaction hash.
- `execution_scopes`, `target_topology`, `test_vectors`, `execution_traces`: as previously scoped.

Transient branching remains at the provider level: every step and vector executes inside `evm_snapshot` / `evm_revert` boundaries on the caller's local fork (Anvil/revm in-memory state), never against live mainnet.

### Multi-step PoC chain runner

`DynamicVerificationSubAgent.execute_poc_chain(chain_label, objective, steps)` runs a list of `ChainStep(target_address, calldata, expected_pre, step_note)`:

1. Takes an outer snapshot for the whole chain.
2. For each step takes a step snapshot, compares every `expected_pre` slot against live storage, submits the transaction through the Ape execution path, then rolls back the step snapshot.
3. Marks steps `PRECONDITION_MISMATCH`, `REVERTED`, `EXECUTION_ERROR`, or `CONFIRMED`; a failed step fails the chain.
4. Persists every step and the chain status, and restores the outer snapshot so a confirmed chain can be replayed cleanly.

The orchestrator exposes `MasterOrchestratorAgent.execute_poc_chain(...)` (synchronous wrapper) for callers that already created the fork.

### New static detectors

`ASTCFGAnalysisWorker` now also emits, from Slither metadata only (no keyword heuristics):

- `ARBITRARY_EXTERNAL_CALL` — low-level calls whose destination is influenced by function parameters.
- `METAMORPHIC_SELFDESTRUCT` — unprotected `selfdestruct` paths relevant to CREATE2 redeployment swaps.
- `CONTROLLED_DELEGATECALL` is now split into argument-influenced delegation and unprotected delegation.
- `ROLE_MAPPING_ESCALATION` is reserved as a `VectorClass` for mapping-slot tracking of role assignments (Slither symbolic-key extraction still pending).

### Toolchain availability bridge

`ToolchainAvailability.survey()` deterministically reports whether `slither`, `z3`, `ape`, `anvil`, `forge`, and `cast` are present. It never launches external engines and never fabricates results; missing engines are reported as facts, and callers decide whether to run external fuzzers/symbolic executors themselves.

## Dependencies

`requirements.txt` currently declares:

```text
eth-ape>=0.7.0
slither-analyzer>=0.10.0
z3-solver>=4.12.0
eth-hash>=0.7.0
```

The environment used for the focused checks did not have Ape, Slither, Z3, Foundry, or a live provider installed. Therefore, real Slither parsing and real Ape transaction behavior still need verification in the target environment.

## Verification completed

The following checks passed:

```bash
python3 -m unittest -v test_unified_security_harness.py
python3 -m py_compile unified_security_harness.py test_unified_security_harness.py
git diff --check
```

Focused unit coverage currently verifies (10 tests, all passing):

- Raw snapshot ID preservation and rollback
- Ape-style preflight followed by account transaction submission
- `ContractLogicError` classification and raw revert preservation
- Live storage-to-constraint bridge
- Scoped SQLite topology/vector/trace persistence
- PoC chain precondition enforcement and per-step rollback
- Transaction-cache and taxonomy persistence round trips
- Deterministic toolchain availability survey

The unit test provider/account doubles are isolated test doubles; they are not used by the production default path and do not start a fork.

## Known limitations and next steps

1. **No real fork has been started.** Select the actual Enzyme Blue deployed target address, fork block, and provider endpoint. Do not use a live-mainnet transaction path.
2. **Install and verify dependencies** in the runtime environment, then run a real Ape local-network smoke test.
3. **Verify Ape version compatibility** for `ecosystem.create_transaction()`, `ProviderAPI.send_call()`, `AccountAPI.call()`, and receipt error fields.
4. **Run real Slither analysis** against the scoped Enzyme repository and confirm storage layout shapes across inherited contracts and proxy implementations.
5. **Improve mapping analysis**: the harness tracks mapping base slots from Slither and computes concrete mapping slots when a key is supplied, but automatic extraction of every symbolic mapping key from SlithIR still needs work.
6. **Add durable SQLite configuration** and migration handling if the database must survive across assessment runs.
7. **Add transaction trace persistence** if Ape provider trace output is required in addition to storage diffs and receipt data.
8. **Complete role-mapping escalation detection** by extracting symbolic mapping keys from SlithIR; the vector class exists but no automatic detector emits it yet.
9. **Optional external engines** (Echidna, ItyFuzz, Halmos, Manticore, Tenderly/Phalcon export, cross-chain debuggers) are intentionally not invoked implicitly. `ToolchainAvailability.survey()` reports their prerequisites; wire them as explicit, opt-in caller steps only.
10. **Web3 threat-intel scanning** (malicious-contract signatures, honeypot detection): no catalog service was available, so this remains a documented taxonomy/data-model category rather than a wired integration.
11. **Do not add a toy fallback or mock provider to production code.** Keep deterministic doubles confined to tests.

## Safe invocation shape

The caller owns fork setup and account loading. The production flow should conceptually be:

```python
scope = TargetScope.enzyme_blue(
    scope_id="enzyme-blue-<assessment-id>",
    target_address="<validated-mainnet-address>",
    fork_block=<validated-block>,
    rpc_url="<local-fork-provider>",
    clone_id="<dedicated-clone-id>",
)

# Caller enters an Ape local fork network and loads the authorized signer.
report = await run_scoped_task(
    scope=scope,
    target_address=scope.normalized_target,
    contract_path="<scoped-source-path>",
    contract_name="<scoped-contract-name>",
)
```

The fork must remain local and isolated. The harness itself does not fork, deploy, mutate live mainnet, or select a target address.
