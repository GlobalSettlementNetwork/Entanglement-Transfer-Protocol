# GSX Pre-Blockchain Roadmap: Trust Packaging and Protocol Hardening

---

## Section 1: Executive Summary

GSX has completed two foundational layers: the dual-lane cryptographic architecture and the real backend integration. The Level 3 primitives (ML-KEM-768, ML-DSA-65, XChaCha20-Poly1305, SHA3-256, BLAKE3) are executing real cryptographic math. The commitment log is append-only with RFC 6962 Merkle proofs and ML-DSA-signed tree heads. Erasure coding, shard placement, audit challenges, staking, and compliance controls are operational.

**What is missing is the trust-packaging layer** — the set of structures that sit between the protocol core and the blockchain. Right now, the system can commit, seal, and materialize data, but it cannot produce a portable, independently verifiable bundle of evidence that a regulator, auditor, smart contract, or cross-chain verifier could evaluate without running a full LTP node.

The next phase builds the **canonical trust artifacts** that smart contracts will anchor. This means: deterministic serialization that is bit-for-bit reproducible, structured approval receipts, systematic domain separation, replay-safe sequencing, portable Merkle proofs, a standalone verification library, and a clear off-chain/on-chain responsibility split. None of this requires writing smart contracts yet. All of it is required before smart contracts can be written correctly.

**The guiding principle:** Smart contracts should anchor hashes, roots, signer references, receipt fingerprints, policy hashes, and state transitions. They should not perform PQ signature verification or heavy computation on-chain. The off-chain layer must produce artifacts that are cheap to verify on-chain but impossible to forge off-chain.

---

## Section 2: Recommended Pre-Blockchain Components

### 2.1 Canonical Object Encoding (COE)

**Objective:** Define a single, deterministic, versioned binary encoding for every protocol object that participates in hashing or signing. Bit-for-bit reproducibility across implementations, languages, and platforms.

**Why it matters:** The codebase currently uses two serialization strategies — struct-packed binary (CommitmentRecord.signable_payload, STH) and canonical JSON (LatticeKey._plaintext_payload). The JSON path is fragile: Python's `json.dumps(sort_keys=True)` does not guarantee cross-language determinism for floats, Unicode normalization, or key ordering edge cases. Any object whose hash or signature is anchored on-chain must have a single canonical byte representation. If two implementations serialize the same logical object differently, signatures won't verify and Merkle proofs will fail.

**Current state:**
- `CommitmentRecord.signable_payload()` uses struct-packed binary with `b"LTP-COMMIT-v1\x00"` prefix — this is close to correct but ad hoc
- `CommitmentRecord.to_bytes()` uses `b"LTP-RECORD-v1\x00"` prefix — similar
- `LatticeKey._plaintext_payload()` uses `json.dumps(sort_keys=True, separators=(',',':'))` — not safe for cross-language determinism
- `SignedTreeHead` signable payload uses struct-packed binary — close to correct
- `AuditEvent` uses `to_dict()` → JSON — not canonical

**What to build:**
- A `CanonicalEncoder` module that encodes any protocol object to a deterministic byte sequence
- Encoding rules: length-prefixed fields, fixed-width integers (big-endian), IEEE 754 doubles (big-endian), length-prefixed UTF-8 strings, sorted-key maps with length-prefixed entries, version prefix on every object type
- Every protocol object gets a `canonical_bytes() -> bytes` method that delegates to this encoder
- Every hash and signature input must pass through `canonical_bytes()`, never through ad hoc serialization
- Migration: refactor `signable_payload()`, `to_bytes()`, and `_plaintext_payload()` to use the shared encoder

**Layer:** Canonical trust boundary

**Dependencies:** None — this is foundational

---

### 2.2 Domain Separation Registry

**Objective:** Systematically assign unique context tags to every hash and signature context in the protocol, preventing cross-context collision attacks.

**Why it matters:** Domain separation prevents an attacker from taking a valid hash or signature from one context and replaying it in another. Currently, domain separation is ad hoc:
- CommitmentRecord uses `b"LTP-COMMIT-v1\x00"` and `b"LTP-RECORD-v1\x00"`
- Merkle tree uses `0x00` (leaf) and `0x01` (internal) per RFC 6962
- AEAD keystream uses `b"aead-auth-tag-key"` context
- ML-KEM PoC simulation uses `b"mlkem-dk"`, `b"mlkem-ek"`, etc.
- No domain separation on ML-DSA signatures (the real backend signs raw message bytes)
- No domain separation on entity ID computation
- No domain separation on shard nonce derivation

If an entity ID hash and a commitment record hash happen to collide (because they hash different structures with the same bytes), an attacker could substitute one for the other. Domain separation makes this structurally impossible.

**What to build:**
- A `DomainSeparation` registry module with named constants:
  ```
  DOMAIN_ENTITY_ID          = b"GSX-LTP:entity-id:v1\x00"
  DOMAIN_COMMIT_SIGN        = b"GSX-LTP:commit-sign:v1\x00"
  DOMAIN_COMMIT_RECORD      = b"GSX-LTP:commit-record:v1\x00"
  DOMAIN_STH_SIGN           = b"GSX-LTP:sth-sign:v1\x00"
  DOMAIN_SHARD_NONCE        = b"GSX-LTP:shard-nonce:v1\x00"
  DOMAIN_SHARD_TREE_LEAF    = b"GSX-LTP:shard-tree-leaf:v1\x00"
  DOMAIN_APPROVAL_RECEIPT   = b"GSX-LTP:approval-receipt:v1\x00"
  DOMAIN_ANCHOR_DIGEST      = b"GSX-LTP:anchor-digest:v1\x00"
  DOMAIN_BRIDGE_MSG         = b"GSX-LTP:bridge-msg:v1\x00"
  ```
- Every `canonical_hash(data)` call that feeds into a trust artifact must prepend the appropriate domain tag
- ML-DSA signatures must sign `domain_tag || canonical_bytes(object)`, not raw message bytes
- Merkle leaf hashing already uses RFC 6962 domain separation — extend this pattern to shard trees and audit proofs

**Layer:** Canonical trust boundary

**Dependencies:** 2.1 (Canonical Object Encoding)

---

### 2.3 Signed Message Envelope

**Objective:** Define a universal wrapper for any protocol message that requires authentication: signer identity, context, timestamp, payload, and ML-DSA signature.

**Why it matters:** Currently, signing is embedded directly into each object (CommitmentRecord.sign(), STH signing). There is no standard envelope that external verifiers can parse generically. A smart contract or auditor receiving a signed artifact needs to know: who signed it, what domain context applies, when it was signed, and what was signed — without understanding the inner payload structure.

**What to build:**
```
SignedEnvelope {
    version:        uint8           # Envelope format version
    domain:         bytes           # Domain separation tag
    signer_vk:      bytes           # ML-DSA-65 verification key (1952 bytes)
    signer_id:      string          # Human-readable signer identifier
    timestamp:      float64         # Signing time (IEEE 754 big-endian)
    payload_type:   string          # "commitment-record", "approval-receipt", "sth", etc.
    payload_hash:   bytes           # H(canonical_bytes(payload)) — for on-chain anchoring
    payload:        bytes           # canonical_bytes(inner object)
    signature:      bytes           # ML-DSA-65 over (domain || canonical_bytes(envelope fields except signature))
}
```

- `SignedEnvelope.verify(vk) -> bool` checks signature without knowing payload type
- `SignedEnvelope.fingerprint() -> str` returns `canonical_hash(domain || payload_hash || signer_vk[:32] || timestamp)` — this is what gets anchored on-chain
- Existing CommitmentRecord.sign() and STH signing refactored to produce SignedEnvelopes internally

**Layer:** Canonical trust boundary

**Dependencies:** 2.1, 2.2

---

### 2.4 Approval Receipt Structure

**Objective:** Define the trust artifact that represents a completed, verified protocol action — the thing that gets anchored on-chain.

**Why it matters:** The protocol currently has no receipt. `commit()` returns `(entity_id, record, cek)`. `materialize()` returns content bytes or None. There is no structured proof that a specific action was performed by a specific signer at a specific time, verified against specific evidence. Smart contracts need to anchor receipts, not raw protocol state.

**What to build:**
```
ApprovalReceipt {
    receipt_id:         string      # canonical_hash(canonical_bytes(this receipt, excluding receipt_id))
    receipt_type:       enum        # COMMIT, MATERIALIZE, SHARD_AUDIT_PASS, KEY_ROTATION, DELETION, GOVERNANCE
    entity_id:          string      # The entity this receipt concerns
    action_summary:     string      # Human-readable action description
    timestamp:          float64     # When the action occurred
    epoch:              uint64      # Protocol epoch
    sequence:           uint64      # Monotonic per-signer sequence number (replay protection)

    # Evidence references (hashes, not full objects)
    commitment_ref:     string      # H(CommitmentRecord.to_bytes())
    sth_ref:            string      # H(SignedTreeHead) at time of action
    merkle_root:        bytes       # Tree root at time of receipt
    inclusion_proof:    bytes       # Merkle inclusion proof (portable format)

    # Signer
    signer_vk:          bytes       # ML-DSA-65 verification key
    signer_role:        string      # RBAC role at time of signing

    # Policy
    policy_hash:        string      # H(access_policy) — ties receipt to governing policy
    jurisdiction:       string      # Jurisdiction context

    # Signature
    signature:          bytes       # ML-DSA-65 over DOMAIN_APPROVAL_RECEIPT || canonical_bytes(all fields above)
}
```

- `ApprovalReceipt.anchor_digest() -> bytes` returns the 32-byte value suitable for on-chain anchoring: `canonical_hash(DOMAIN_ANCHOR_DIGEST || receipt_id || signer_vk[:32] || merkle_root || sequence)`
- `ApprovalReceipt.verify(signer_vk) -> bool` checks the ML-DSA signature
- `ApprovalReceipt.to_evidence_bundle() -> dict` packages the receipt with its inclusion proof and STH for regulator export

**Layer:** Canonical trust boundary (this IS the trust anchor that bridges off-chain and on-chain)

**Dependencies:** 2.1, 2.2, 2.3, 2.6

---

### 2.5 Replay Protection, Sequencing, and Idempotency

**Objective:** Ensure every trust artifact is unique, ordered, and cannot be replayed across signers, chains, or time windows.

**Why it matters:** The existing `NonceTracker` in `bridge/nonce.py` is a basic high-water-mark per (source_chain, sender). This is insufficient for on-chain anchoring because:
- There is no per-signer monotonic sequence number on approval receipts
- There is no chain-binding (an artifact signed for chain A could be submitted to chain B)
- There is no expiry window (a valid artifact from 2024 could be submitted in 2027)
- CommitmentRecord has no sequence number — only a predecessor hash

**What to build:**
- **Per-signer sequence counter:** Every signer maintains a monotonically increasing uint64 sequence. Each SignedEnvelope and ApprovalReceipt includes the signer's current sequence. Verifiers reject any sequence <= last seen for that signer.
- **Chain binding:** Every artifact destined for on-chain anchoring includes a `target_chain_id` field. The smart contract rejects artifacts bound to a different chain.
- **Expiry window:** Every artifact includes a `valid_until` timestamp. The smart contract rejects artifacts whose expiry has passed. Recommended window: 1 hour for real-time anchoring, 24 hours for batch anchoring.
- **Idempotency key:** `receipt_id` serves as the idempotency key. The smart contract stores a set of anchored receipt_ids and rejects duplicates.
- **NonceTracker upgrade:** Extend to track per-signer sequences, validate chain binding, enforce expiry windows, and support batch validation.

**Layer:** Canonical trust boundary + blockchain preparation

**Dependencies:** 2.3, 2.4

---

### 2.6 Portable Merkle Proof Format

**Objective:** Define a self-contained, independently verifiable Merkle proof structure that can be verified on-chain, by auditors, or by cross-chain bridges without access to the full tree.

**Why it matters:** The current `MerkleTree.audit_path()` returns `list[bytes]` — a list of sibling hashes. This is correct but not portable: a verifier needs to know the leaf index, tree size, leaf hash, direction bits, and the root to verify against. The current `get_inclusion_proof()` returns a dict but it's not standardized. For on-chain verification, the proof must be compact and parseable by a smart contract.

**What to build:**
```
MerkleInclusionProof {
    version:        uint8
    tree_type:      enum        # COMMITMENT_LOG, SHARD_TREE, AUDIT_LOG
    leaf_index:     uint64
    tree_size:      uint64
    leaf_hash:      bytes[32]   # H(0x00 || leaf_data)
    root_hash:      bytes[32]   # Expected root
    path:           list[bytes[32]]  # Sibling hashes, bottom to top
    path_directions: bitfield   # 0 = sibling on right, 1 = sibling on left
}
```

- `MerkleInclusionProof.verify() -> bool` reconstructs root from leaf + path and compares
- `MerkleInclusionProof.to_bytes() -> bytes` compact binary encoding for on-chain submission
- `MerkleInclusionProof.solidity_calldata() -> bytes` ABI-encoded for direct contract call (future)
- Refactor `CommitmentLog.get_inclusion_proof()` to return this structure
- Add `MerkleConsistencyProof` for log consistency verification (proves log-1 is a prefix of log-2)

**Layer:** Canonical trust boundary + blockchain preparation

**Dependencies:** 2.1

---

### 2.7 Signer Governance and Policy

**Objective:** Define who can sign what, under what conditions, and how signer authority is established, rotated, and revoked.

**Why it matters:** Currently, any KeyPair can sign any CommitmentRecord. There is no governance layer that restricts signing authority. Before on-chain anchoring, the system needs:
- A signer registry that maps verification keys to roles and permissions
- Multi-signer approval policies (e.g., "commitment requires operator + compliance officer")
- Key rotation that preserves signer identity across key generations
- Revocation that invalidates a compromised key's past signatures (or explicitly does not, depending on policy)
- A policy hash that can be anchored on-chain so the contract knows which governance rules were in effect

**What to build:**
```
SignerPolicy {
    policy_id:          string      # H(canonical_bytes(this policy))
    policy_version:     uint32
    effective_epoch:    uint64
    expires_epoch:      uint64      # Optional

    # Signer registry
    signers: list[SignerEntry] {
        signer_id:      string
        vk:             bytes       # ML-DSA-65 verification key
        roles:          set[ComplianceRole]
        permissions:    set[Permission]
        valid_from:     uint64      # Epoch
        valid_until:    uint64      # Epoch (key expiry)
        predecessor_vk: bytes       # Previous vk (for rotation chain)
    }

    # Approval rules
    approval_rules: list[ApprovalRule] {
        action_type:    enum        # COMMIT, MATERIALIZE, ANCHOR, ROTATE, REVOKE
        required_roles: set[ComplianceRole]
        min_signers:    uint8       # Quorum threshold
        max_age_seconds: uint32     # Signature freshness requirement
    }

    # Policy signature (self-referential: signed by ADMIN or GOVERNANCE role)
    policy_signature:   bytes
    policy_signer_vk:   bytes
}
```

- `SignerPolicy.policy_hash() -> str` is what gets anchored on-chain
- Smart contract stores `active_policy_hash` and rejects receipts signed under a revoked policy
- `SignerPolicy.verify_receipt(receipt) -> bool` checks: signer is in registry, signer has required role, signer's key is not expired/revoked, receipt sequence is valid, approval rule quorum is met
- Integrate with existing `RBACManager` and `KeyRotationManager`

**Layer:** Canonical trust boundary + blockchain preparation

**Dependencies:** 2.3, 2.4, existing RBAC and KeyRotation systems

---

### 2.8 Verification SDK

**Objective:** Build a standalone library that can verify any GSX trust artifact — approval receipts, Merkle proofs, ML-DSA signatures, signed envelopes, signer policies — without running a full LTP node or having access to shard data.

**Why it matters:** External parties (auditors, regulators, smart contracts, cross-chain bridges, counterparty systems) need to verify GSX trust artifacts independently. The current codebase is monolithic — verification logic is embedded in protocol methods alongside commit/materialize logic. A standalone verifier decouples trust verification from protocol operation.

**What to build:**
- `gsxverify` package (or `ltp.verify` subpackage) with zero dependency on protocol state:
  - `verify_signature(vk, domain, message_bytes) -> bool` — ML-DSA-65 verification
  - `verify_envelope(envelope: SignedEnvelope) -> VerificationResult` — checks signature, domain, signer
  - `verify_receipt(receipt: ApprovalReceipt, policy: SignerPolicy) -> VerificationResult` — checks signature, sequence, signer authority, freshness, policy compliance
  - `verify_merkle_proof(proof: MerkleInclusionProof) -> bool` — reconstructs root
  - `verify_commitment_chain(records: list[CommitmentRecord]) -> ChainVerificationResult` — checks predecessor linkage, signatures, Merkle consistency
  - `verify_sth(sth: SignedTreeHead, operator_vk: bytes) -> bool`
  - `parse_anchor_digest(digest: bytes) -> AnchorDigestComponents` — decompose on-chain anchor back into verifiable components
- All verification functions are **pure**: no network calls, no state, no side effects
- Input is canonical bytes (produced by COE), output is a structured result with pass/fail and evidence
- This SDK is what would eventually be ported to Solidity/Rust for on-chain verification of compact proofs

**Layer:** Verification boundary (bridges canonical trust boundary to external consumers)

**Dependencies:** 2.1, 2.2, 2.3, 2.4, 2.6, 2.7

---

### 2.9 Off-Chain vs On-Chain Responsibility Split

**Objective:** Define exactly which data and logic lives off-chain (LTP nodes) vs on-chain (smart contracts), and what crosses the boundary.

**Why it matters:** Putting too much on-chain is expensive and leaks privacy. Putting too little on-chain makes the chain a rubber stamp. The split must be deliberate.

**Recommended split:**

| Responsibility | Location | Rationale |
|---------------|----------|-----------|
| Shard storage and retrieval | Off-chain | Too large for chain, privacy-sensitive |
| Erasure coding/decoding | Off-chain | Computation-intensive, no trust value on-chain |
| ML-KEM encapsulation/decapsulation | Off-chain | Per-message forward secrecy, no chain visibility needed |
| AEAD encryption/decryption | Off-chain | Transport security, not a trust anchor |
| ML-DSA signature generation | Off-chain | Private key must never touch chain |
| ML-DSA signature verification | Off-chain (primary), on-chain (anchor verification only) | PQ sig verification is expensive; anchor digests are cheap |
| CommitmentRecord creation and signing | Off-chain | Complex object, signed off-chain |
| Approval receipt creation | Off-chain | Signed off-chain, anchored on-chain |
| Merkle proof generation | Off-chain | Requires full tree |
| Merkle proof verification | Both | Off-chain for full verification; on-chain for anchor checks |
| Signer policy publication | On-chain | Authoritative signer registry |
| Policy hash anchoring | On-chain | Immutable governance record |
| Receipt anchor digest storage | On-chain | Immutable proof of action |
| Merkle root anchoring | On-chain | Immutable state commitment |
| Sequence/nonce tracking | On-chain | Replay prevention |
| Signer registration/revocation | On-chain | Authoritative identity |
| State transitions (COMMITTED, ANCHORED, MATERIALIZED) | On-chain | Authoritative lifecycle |
| Dispute initiation and resolution | On-chain | Needs chain finality |
| Stake escrow and slashing | On-chain | Economic security |

**What crosses the boundary (off-chain -> on-chain):**
1. `anchor_digest` (32 bytes) — compact fingerprint of an approval receipt
2. `merkle_root` (32 bytes) — commitment log state at anchoring time
3. `policy_hash` (32 bytes) — governance policy fingerprint
4. `signer_vk_hash` (32 bytes) — signer identity reference
5. `sequence` (uint64) — replay protection counter
6. `target_chain_id` (uint256) — chain binding
7. `valid_until` (uint64) — expiry timestamp

Total on-chain storage per anchor: ~200 bytes. This is deliberately minimal.

**Layer:** Blockchain preparation

**Dependencies:** 2.4, 2.5, 2.7, 2.8

---

### 2.10 On-Chain Anchoring Strategy

**Objective:** Design the smart contract state model, event emissions, and verification logic that anchors GSX trust artifacts on-chain.

**Why it matters:** The contract is the authoritative public record. Its design determines gas costs, upgrade path, cross-chain bridgeability, and auditability.

**Recommended contract architecture:**

```
GSXAnchorRegistry {
    // State
    mapping(bytes32 => AnchorRecord) public anchors;      // anchor_digest => record
    mapping(address => uint64) public signerSequences;      // signer => last sequence
    mapping(bytes32 => bool) public activePolicies;         // policy_hash => active
    mapping(bytes32 => SignerInfo) public signerRegistry;   // vk_hash => signer info
    bytes32 public currentMerkleRoot;                       // Latest anchored root
    uint64 public anchorCount;                              // Total anchors

    // Anchor record (stored on-chain)
    struct AnchorRecord {
        bytes32 anchorDigest;       // H(receipt)
        bytes32 merkleRoot;         // Tree root at anchor time
        bytes32 policyHash;         // Governing policy
        bytes32 signerVkHash;       // H(signer_vk)
        uint64 sequence;            // Signer's sequence number
        uint64 timestamp;           // Anchor time
        uint64 validUntil;          // Expiry
        uint8 receiptType;          // COMMIT, MATERIALIZE, etc.
        bool exists;                // Existence flag
    }

    // Events (the primary interface for indexers and auditors)
    event Anchored(bytes32 indexed anchorDigest, bytes32 indexed signerVkHash, uint8 receiptType, uint64 sequence);
    event PolicyActivated(bytes32 indexed policyHash, bytes32 signerVkHash);
    event PolicyRevoked(bytes32 indexed policyHash, bytes32 signerVkHash);
    event SignerRegistered(bytes32 indexed vkHash, bytes32 policyHash);
    event SignerRevoked(bytes32 indexed vkHash, uint64 revokedAtSequence);
    event MerkleRootAdvanced(bytes32 indexed newRoot, bytes32 previousRoot, uint64 treeSize);

    // Core functions
    function anchor(AnchorSubmission calldata submission) external;
    function batchAnchor(AnchorSubmission[] calldata submissions) external;
    function activatePolicy(bytes32 policyHash, bytes calldata policySignature) external;
    function registerSigner(bytes32 vkHash, bytes32 policyHash) external;
    function revokeSigner(bytes32 vkHash) external;
    function advanceMerkleRoot(bytes32 newRoot, uint64 treeSize, bytes calldata sthSignature) external;

    // Verification (view functions)
    function isAnchored(bytes32 anchorDigest) external view returns (bool);
    function getAnchor(bytes32 anchorDigest) external view returns (AnchorRecord memory);
    function isSignerActive(bytes32 vkHash) external view returns (bool);
    function isPolicyActive(bytes32 policyHash) external view returns (bool);
    function verifySequence(bytes32 signerVkHash, uint64 sequence) external view returns (bool);
}
```

**Key design decisions:**
- **No PQ verification on-chain:** ML-DSA-65 signatures are verified off-chain. The contract trusts the anchor digest (which is a commitment to the signature). Full signature verification happens in the Verification SDK.
- **Batch anchoring:** Multiple receipts can be anchored in a single transaction to amortize gas.
- **Event-driven:** Indexers and auditors consume events, not storage reads. Events are cheap and permanent.
- **Upgradeable:** Use proxy pattern (EIP-1967) so the contract can be upgraded without losing state.

**Layer:** Blockchain preparation

**Dependencies:** 2.4, 2.5, 2.7, 2.9

---

### 2.11 Threat Modeling and Failure States

**Objective:** Identify and mitigate attack surfaces at the boundary between off-chain protocol and on-chain anchoring.

**Key threats:**

| Threat | Impact | Mitigation |
|--------|--------|------------|
| **Compromised signer key** | Attacker signs fraudulent receipts | On-chain signer revocation with `revokedAtSequence`; all receipts with sequence > revocation are invalid. Key rotation via `predecessor_vk` chain. |
| **Replay across chains** | Valid receipt for chain A submitted to chain B | `target_chain_id` field in every artifact; contract rejects mismatched chain IDs |
| **Replay across time** | Old valid receipt re-submitted | `valid_until` expiry + `sequence` monotonicity; contract rejects expired or out-of-sequence submissions |
| **Equivocating log operator** | Operator signs two different tree heads for the same sequence | `SignedTreeHead` equivocation detection (already exists in MerkleLog); on-chain `advanceMerkleRoot` rejects non-monotonic tree sizes |
| **Anchor digest collision** | Two different receipts produce same anchor_digest | Domain separation + canonical encoding make this computationally infeasible (SHA3-256 collision resistance) |
| **Chain reorganization** | Anchored receipt is orphaned by reorg | Wait for sufficient confirmations before treating anchor as final; materialization should check anchor finality |
| **Signer policy downgrade** | Attacker activates a weaker policy | Policy activation requires existing ADMIN/GOVERNANCE signer; on-chain `activatePolicy` checks signature authority |
| **Merkle root manipulation** | Attacker advances root to include fraudulent records | Root advancement requires operator STH signature; consistency proofs verify old root is prefix of new root |
| **Denial of anchoring** | Operator refuses to anchor valid receipts | Receipt is independently verifiable off-chain via Verification SDK; alternative operators can anchor the same receipt |
| **HSM boundary breach** | Private key extracted from software HSM | SoftwareHSM is PoC only; production requires PKCS#11 HSM. Key destruction zeroization already implemented. |

**Layer:** Security boundary (spans all layers)

**Dependencies:** 2.4, 2.5, 2.7, 2.10

---

### 2.12 Regulator-Facing Evidence Packaging

**Objective:** Produce self-contained evidence bundles that a regulator or auditor can independently verify, without running LTP software or accessing the network.

**Why it matters:** Banking regulators (OCC, FCA, MAS) and auditors (Big Four) need to verify compliance claims independently. They will not install Python packages or run LTP nodes. They need a document-like artifact with embedded proofs.

**What to build:**
```
EvidenceBundle {
    bundle_id:          string
    bundle_type:        enum        # COMMITMENT_EVIDENCE, MATERIALIZATION_EVIDENCE, AUDIT_EVIDENCE, DELETION_EVIDENCE
    created_at:         float64
    subject_entity_id:  string

    # The primary trust artifacts
    approval_receipts:  list[ApprovalReceipt]        # Signed receipts for this entity
    commitment_record:  CommitmentRecord              # The original commitment
    signed_tree_heads:  list[SignedTreeHead]          # STHs bracketing the action
    merkle_proofs:      list[MerkleInclusionProof]    # Inclusion proofs for each receipt/record

    # Governance context
    signer_policy:      SignerPolicy                  # Policy in effect at time of action
    signer_chain:       list[SignerEntry]             # Key rotation history for each signer

    # Compliance metadata
    jurisdiction:       string
    framework:          string                        # SOC2, FedRAMP, GDPR, etc.
    audit_events:       list[AuditEvent]              # Relevant audit log entries

    # Verification instructions
    verification_spec:  string                        # Version of verification algorithm
    hash_algorithm:     string                        # "SHA3-256"
    signature_algorithm: string                       # "ML-DSA-65"

    # Bundle integrity
    bundle_hash:        string                        # H(canonical_bytes(all above))
    bundle_signature:   bytes                         # Operator signature over bundle_hash
}
```

- `EvidenceBundle.verify(operator_vk) -> VerificationResult` uses the Verification SDK to check every artifact in the bundle
- Export formats: JSON (human-readable), CBOR (compact), PDF (with embedded verification data for non-technical reviewers)
- Each bundle is self-contained: a verifier needs only the bundle and the Verification SDK, not network access

**Layer:** Canonical trust boundary + compliance

**Dependencies:** 2.1, 2.3, 2.4, 2.6, 2.7, 2.8

---

### 2.13 Cross-L2 / Cross-Domain Materialization Preparation

**Objective:** Define how trust artifacts, anchor references, and materialization proofs travel between L2 chains or independent GSX domains.

**Why it matters:** GSX's value proposition includes cross-L2 data materialization. A commitment anchored on Arbitrum must be materializable by a receiver on Optimism. This requires a bridge message format, cross-chain proof verification, and a trust model for relay operators.

**What to build:**
```
BridgeMessage {
    version:            uint8
    source_chain_id:    uint256
    target_chain_id:    uint256
    message_type:       enum        # ANCHOR_RELAY, MATERIALIZATION_REQUEST, PROOF_RELAY, SIGNER_SYNC
    nonce:              uint64      # Per (source_chain, sender) monotonic
    sender_vk_hash:     bytes32     # Signer on source chain

    # Payload (one of)
    anchor_relay: {
        anchor_digest:  bytes32
        merkle_root:    bytes32
        source_anchor_tx: bytes32   # Transaction hash on source chain (for verification)
    }

    materialization_proof: {
        entity_id:      string
        commitment_ref: string
        inclusion_proof: MerkleInclusionProof
        receipt_ref:    bytes32     # Anchor digest of the commitment receipt
    }

    # Signature
    relay_signature:    bytes       # ML-DSA-65 by relay operator
    relay_vk:           bytes       # Relay operator's verification key
}
```

- Bridge messages use the same canonical encoding, domain separation, and signed envelope as local artifacts
- Cross-chain nonce tracking extends `NonceTracker` with chain-pair isolation
- Trust model: relay operators are registered signers with RELAY role in the signer policy; target chain contract verifies relay is authorized
- The existing `FederatedNetwork` and `EntityResolution` structures in `federation.py` provide the discovery layer; bridge messages provide the trust transport

**Layer:** Blockchain preparation + cross-chain

**Dependencies:** 2.1, 2.2, 2.5, 2.6, 2.7, 2.10

---

### 2.14 Hybrid Crypto and Migration Planning

**Objective:** Plan for the transition when FIPS-validated PQ modules become available, when pqcrypto library APIs change, or when algorithm parameters are updated.

**Why it matters:** The current `pqcrypto` library implements FIPS 203/204 algorithms but is not FIPS 140-3 validated. When validated modules (liboqs FIPS, hardware HSM PQ support) become available, the system must migrate without breaking existing signatures, proofs, or on-chain anchors.

**What to build:**
- **Algorithm agility in canonical encoding:** Every signed/hashed artifact includes an `algorithm_id` field that specifies exactly which algorithm and parameter set produced it. Example: `"ML-DSA-65-pqcrypto-0.3"` vs `"ML-DSA-65-liboqs-0.11-fips"`.
- **Signature format versioning:** The SignedEnvelope `version` field allows future envelopes to use different signature algorithms without breaking parsers.
- **Key migration protocol:** When a signer rotates from one backend to another, the new key signs a migration statement that includes the old vk, enabling verifiers to chain trust across backends.
- **On-chain algorithm registry:** The smart contract stores a mapping of `algorithm_id => status` (ACTIVE, DEPRECATED, REVOKED). Anchors made with a deprecated algorithm are still valid but new anchors must use ACTIVE algorithms.
- **Dual-signature transition period:** During migration, critical artifacts can carry two signatures (old backend + new backend). Verifiers accept either. After transition period, old signatures are no longer accepted for new artifacts.

**Layer:** All layers (this is a cross-cutting concern)

**Dependencies:** 2.2, 2.3, 2.7

---

## Section 3: Priority Order

### Tier 1: Immediate (Required before any blockchain work)

| Priority | Component | Rationale |
|----------|-----------|-----------|
| **1** | 2.1 Canonical Object Encoding | Everything else depends on deterministic serialization |
| **2** | 2.2 Domain Separation Registry | Required for secure hashing and signing in all subsequent components |
| **3** | 2.3 Signed Message Envelope | Standardizes authentication for all trust artifacts |
| **4** | 2.4 Approval Receipt Structure | The primary trust artifact — what smart contracts will anchor |
| **5** | 2.5 Replay Protection & Sequencing | Receipts are useless without replay safety |

### Tier 2: Required before smart contract deployment

| Priority | Component | Rationale |
|----------|-----------|-----------|
| **6** | 2.6 Portable Merkle Proof Format | On-chain verification needs portable proofs |
| **7** | 2.7 Signer Governance & Policy | Contract needs to know who can anchor what |
| **8** | 2.9 Off-Chain/On-Chain Split | Must be finalized before writing contract code |
| **9** | 2.10 On-Chain Anchoring Strategy | Contract ABI and state design |
| **10** | 2.8 Verification SDK | External verification of all artifacts |

### Tier 3: Required before production deployment

| Priority | Component | Rationale |
|----------|-----------|-----------|
| **11** | 2.11 Threat Modeling | Must be complete before mainnet |
| **12** | 2.12 Evidence Packaging | Regulator-facing compliance |
| **13** | 2.13 Cross-L2 Preparation | Multi-chain materialization |
| **14** | 2.14 Hybrid Crypto Migration | Future-proofing |

---

## Section 4: Suggested Technical Artifacts to Produce

### Specifications

| Artifact | Type | Description |
|----------|------|-------------|
| `COE-SPEC-v1` | Encoding specification | Canonical Object Encoding rules, field types, versioning, test vectors |
| `DOMAIN-SEP-REGISTRY-v1` | Reference document | Complete registry of domain separation tags with collision analysis |
| `SIGNED-ENVELOPE-SPEC-v1` | Message format spec | Envelope structure, signing algorithm, verification algorithm |
| `APPROVAL-RECEIPT-SPEC-v1` | Trust artifact spec | Receipt types, fields, signing rules, anchor digest computation |
| `MERKLE-PROOF-SPEC-v1` | Proof format spec | Inclusion proof, consistency proof, portable encoding, on-chain encoding |
| `SIGNER-POLICY-SPEC-v1` | Governance spec | Signer registry, approval rules, rotation protocol, revocation semantics |
| `ANCHOR-STATE-SPEC-v1` | Contract spec | On-chain state model, events, functions, upgrade strategy |
| `BRIDGE-MESSAGE-SPEC-v1` | Cross-chain spec | Bridge message format, relay trust model, cross-chain nonce protocol |

### Code Modules

| Module | Package Path | Description |
|--------|-------------|-------------|
| Canonical Encoder | `src/ltp/encoding.py` | `CanonicalEncoder` with type-safe field encoding, version prefixes |
| Domain Separation | `src/ltp/domain.py` | `DomainTag` constants, `domain_hash()`, `domain_sign()` wrappers |
| Signed Envelope | `src/ltp/envelope.py` | `SignedEnvelope` dataclass with sign/verify/fingerprint |
| Approval Receipt | `src/ltp/receipt.py` | `ApprovalReceipt` dataclass with anchor_digest/verify/to_evidence |
| Replay Guard | `src/ltp/sequencing.py` | `SequenceTracker`, chain binding, expiry validation |
| Portable Proofs | `src/ltp/merkle_log/proof.py` | `MerkleInclusionProof`, `MerkleConsistencyProof` with compact encoding |
| Signer Policy | `src/ltp/governance.py` | `SignerPolicy`, `SignerEntry`, `ApprovalRule`, policy verification |
| Verification SDK | `src/ltp/verify/` | Standalone package: `verify_receipt()`, `verify_proof()`, `verify_envelope()` |
| Evidence Bundle | `src/ltp/evidence.py` | `EvidenceBundle` with self-contained verification |
| Anchor Client | `src/ltp/anchor/` | Off-chain client that submits anchors to smart contract |

### Test Suites

| Test File | Coverage |
|-----------|----------|
| `tests/test_encoding.py` | Canonical encoding determinism, cross-version compatibility, round-trip |
| `tests/test_domain_separation.py` | No tag collisions, domain isolation, cross-context rejection |
| `tests/test_envelope.py` | Sign/verify, wrong signer, tampered payload, expired envelope |
| `tests/test_receipt.py` | Receipt creation, anchor digest stability, sequence enforcement |
| `tests/test_sequencing.py` | Replay rejection, chain binding, expiry, batch ordering |
| `tests/test_portable_proofs.py` | Proof generation, verification, compact encoding, cross-tree-type |
| `tests/test_governance.py` | Policy creation, signer authority, rotation, revocation, quorum |
| `tests/test_verify.py` | Full verification SDK: receipts, proofs, envelopes, chains |
| `tests/test_evidence.py` | Bundle creation, self-contained verification, export formats |

---

## Section 5: Smart Contract Preparation Without Writing Contracts

### 5.1 State Machine Design

The on-chain entity lifecycle has exactly five states:

```
UNKNOWN -> COMMITTED -> ANCHORED -> MATERIALIZED -> DELETED
                |                        |
                +-----> DISPUTED <-------+
```

**Transitions:**
- `UNKNOWN -> COMMITTED`: First anchor submission for an entity_id (receipt_type = COMMIT)
- `COMMITTED -> ANCHORED`: Merkle root that includes the commitment is advanced on-chain
- `ANCHORED -> MATERIALIZED`: Materialization receipt anchored (receipt_type = MATERIALIZE)
- `ANCHORED -> DISPUTED`: Dispute initiated (receipt_type = DISPUTE)
- `MATERIALIZED -> DELETED`: Deletion receipt anchored (receipt_type = DELETION)
- `DISPUTED -> ANCHORED`: Dispute resolved in favor of validity
- `DISPUTED -> DELETED`: Dispute resolved in favor of deletion

Each transition requires a valid anchor submission with correct receipt_type and passing sequence/policy checks.

### 5.2 Event Emission Strategy

Events are the primary interface for off-chain indexers, auditors, and cross-chain bridges. Design events for indexability:

```solidity
// Indexed fields enable efficient filtering
event EntityCommitted(
    bytes32 indexed entityIdHash,       // H(entity_id) for efficient lookup
    bytes32 indexed signerVkHash,
    bytes32 anchorDigest,
    uint64 sequence,
    uint64 timestamp
);

event MerkleRootAdvanced(
    bytes32 indexed newRoot,
    bytes32 indexed previousRoot,
    uint64 treeSize,
    uint64 timestamp
);

event EntityMaterialized(
    bytes32 indexed entityIdHash,
    bytes32 indexed receiverVkHash,
    bytes32 anchorDigest,
    uint64 timestamp
);

event SignerRegistered(
    bytes32 indexed vkHash,
    bytes32 indexed policyHash,
    uint64 validFrom,
    uint64 validUntil
);
```

### 5.3 ABI Planning

Design function signatures for gas efficiency:

```solidity
// Primary anchoring function — ~60k gas estimated
function anchor(
    bytes32 anchorDigest,
    bytes32 merkleRoot,
    bytes32 policyHash,
    bytes32 signerVkHash,
    uint64 sequence,
    uint64 validUntil,
    uint8 receiptType
) external;

// Batch anchoring — amortizes base cost across multiple anchors
function batchAnchor(
    bytes32[] calldata anchorDigests,
    bytes32 merkleRoot,              // Shared root for batch
    bytes32 policyHash,              // Shared policy for batch
    bytes32 signerVkHash,            // Single signer for batch
    uint64 startSequence,            // First sequence in batch
    uint64 validUntil,
    uint8[] calldata receiptTypes
) external;

// View functions — zero gas for callers
function isAnchored(bytes32 anchorDigest) external view returns (bool);
function entityState(bytes32 entityIdHash) external view returns (uint8 state);
function signerSequence(bytes32 vkHash) external view returns (uint64);
```

### 5.4 Gas Cost Estimates

| Operation | Estimated Gas | Notes |
|-----------|--------------|-------|
| Single anchor | ~60,000 | 1 SSTORE (new) + 1 SSTORE (sequence update) + event |
| Batch anchor (10) | ~350,000 | Amortized ~35k per anchor |
| Advance Merkle root | ~45,000 | 1 SSTORE + event |
| Register signer | ~50,000 | 1 SSTORE + event |
| Revoke signer | ~25,000 | 1 SSTORE update + event |
| Read anchor (view) | 0 | Free for callers |

### 5.5 Upgrade Strategy

- Use EIP-1967 transparent proxy pattern
- Storage layout: leave gaps between struct fields for future additions
- Version all function signatures in case ABI must change
- Governance: proxy admin is a multi-sig or timelock contract, not an EOA

---

## Section 6: Security and Risk Controls

### 6.1 Missing Control Layers

| Control | Current State | Required State | Priority |
|---------|--------------|----------------|----------|
| **Domain separation** | Ad hoc prefixes | Systematic registry with collision analysis | Tier 1 |
| **Replay protection** | Basic NonceTracker in bridge module | Per-signer sequences + chain binding + expiry on all trust artifacts | Tier 1 |
| **Signer authority** | Any KeyPair can sign anything | Role-based signing authority with policy enforcement | Tier 2 |
| **Key revocation** | KeyRotationManager tracks versions but no signature invalidation | On-chain revocation with `revokedAtSequence` | Tier 2 |
| **Anchor finality** | N/A (no chain yet) | Confirmation depth requirement before treating anchor as final | Tier 2 |
| **Rate limiting** | None | Per-signer anchor rate limits to prevent spam | Tier 3 |
| **Merkle root monotonicity** | STH has sequence but not enforced on-chain | Contract rejects non-monotonic tree size advances | Tier 2 |

### 6.2 Attack Surface Analysis

**Off-chain attack surfaces:**
- Compromised signer key: Mitigated by on-chain revocation + sequence invalidation
- Tampered CommitmentRecord: Mitigated by ML-DSA signature + Merkle inclusion proof
- Shard corruption: Mitigated by AEAD tags + erasure coding + storage proof audits
- Log equivocation: Mitigated by STH equivocation detection (already implemented)

**Chain boundary attack surfaces:**
- Anchor replay: Mitigated by per-signer sequence monotonicity
- Cross-chain replay: Mitigated by chain_id binding in anchor digest
- Stale anchor: Mitigated by valid_until expiry
- Policy downgrade: Mitigated by on-chain policy activation requiring authorized signer
- Front-running anchor submission: Low risk — anchors are idempotent (same receipt_id = same anchor_digest)

**On-chain attack surfaces:**
- Contract upgrade attack: Mitigated by timelock + multi-sig proxy admin
- Storage collision: Mitigated by keccak256 mapping keys (standard Solidity)
- Reentrancy: Low risk — anchor contract has no external calls or ETH transfers

### 6.3 Hardening Opportunities

1. **Commitment record binding:** Include `target_chain_id` in `CommitmentRecord.signable_payload()` so a commitment is bound to a specific chain from creation, not just at anchoring time.
2. **Signer freshness proof:** Require signers to periodically submit "liveness" anchors. Signers who haven't anchored in N epochs are automatically suspended (prevents stale key compromise from going undetected).
3. **Merkle consistency proof on root advance:** When `advanceMerkleRoot()` is called, require a compact consistency proof that the new root extends the old root. This prevents root rollback attacks.
4. **Dual-anchor for critical operations:** High-value materializations require anchors on two independent chains. A receipt is only considered final when both chains confirm it.

---

## Section 7: Final Recommendation

**Build the trust-packaging layer before touching smart contracts.**

The crypto primitives are real. The protocol flow works. But between the protocol core and the blockchain, there is currently a gap: no standard way to produce a portable, verifiable, replay-safe, policy-governed trust artifact that a smart contract can cheaply anchor and an auditor can independently verify.

**Start with Canonical Object Encoding and Domain Separation** (components 2.1 and 2.2). These are pure, foundational, and everything else depends on them. They can be implemented and tested in a single focused sprint.

**Then build the Signed Envelope and Approval Receipt** (2.3 and 2.4). These are the actual trust artifacts that will cross the off-chain/on-chain boundary. Once receipts exist, the smart contract interface becomes obvious — it's just anchoring receipt digests and enforcing sequence/policy rules.

**Then build Replay Protection and Signer Governance** (2.5 and 2.7). These ensure receipts are safe to anchor and that the contract knows who can anchor what.

**Then build the Verification SDK** (2.8). This forces you to validate that every artifact is independently verifiable — if the SDK can't verify it without protocol state, it's not portable enough for on-chain anchoring.

**Only then write smart contracts.** By that point, the contract is trivial: it stores 32-byte digests, enforces sequences, checks signer authorization against policy hashes, and emits events. All the hard work — canonical encoding, domain separation, receipt construction, signature verification, Merkle proofs — is done off-chain and validated by the Verification SDK.

The recommended implementation sequence is:

```
COE -> Domain Sep -> Envelope -> Receipt -> Replay -> Merkle Proofs -> Governance -> Verification SDK -> Contract Design -> Contract Code
```

This order ensures that each component can be fully tested before the next one depends on it, and that smart contract code is written last — when the trust model is fully defined and independently verifiable.
