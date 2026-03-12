# LTP Architecture (v2 — Option C Security)

## System Overview

```
┌─────────────────────────────────────────────────────────────────────────┐
│                     LATTICE TRANSFER PROTOCOL v2                    │
│                                                                         │
│  ┌──────────┐  ~1300 bytes     ┌──────────┐                            │
│  │  SENDER  │ ════════════════ │ RECEIVER │                            │
│  │          │  ML-KEM sealed  │          │                            │
│  └────┬─────┘  (opaque)        └────┬─────┘                            │
│       │                             │                                   │
│       │ COMMIT                      │ MATERIALIZE                       │
│       │ (encrypted shards)          │ (unseal → derive → fetch → decrypt)│
│       ▼                             ▼                                   │
│  ┌─────────────────────────────────────────────────────────────────┐   │
│  │                    COMMITMENT LAYER                              │   │
│  │                                                                  │   │
│  │  ┌───────────────────────────────────────────────────────────┐  │   │
│  │  │              COMMITMENT LOG (Append-Only)                  │  │   │
│  │  │                                                            │  │   │
│  │  │  Record 1 ← Record 2 ← Record 3 ← ... ← Record N        │  │   │
│  │  │  (NO shard_ids — Merkle root of ciphertext hashes only)    │  │   │
│  │  └───────────────────────────────────────────────────────────┘  │   │
│  │                                                                  │   │
│  │  ┌───────────────────────────────────────────────────────────┐  │   │
│  │  │           COMMITMENT NODES (Encrypted Shard Storage)       │  │   │
│  │  │                                                            │  │   │
│  │  │  ┌─────┐  ┌─────┐  ┌─────┐  ┌─────┐  ┌─────┐          │  │   │
│  │  │  │ N1  │  │ N2  │  │ N3  │  │ N4  │  │ N5  │  ...     │  │   │
│  │  │  │     │  │     │  │     │  │     │  │     │          │  │   │
│  │  │  │ 🔒  │  │ 🔒  │  │ 🔒  │  │ 🔒  │  │ 🔒  │          │  │   │
│  │  │  │ 🔒  │  │ 🔒  │  │ 🔒  │  │ 🔒  │  │ 🔒  │          │  │   │
│  │  │  └─────┘  └─────┘  └─────┘  └─────┘  └─────┘          │  │   │
│  │  │    (AEAD-encrypted ciphertext — nodes cannot read)       │  │   │
│  │  │    (keyed by (entity_id, index) — derivable by receiver) │  │   │
│  │  └───────────────────────────────────────────────────────────┘  │   │
│  └─────────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## Component Architecture

### 1. Entity Engine

The Entity Engine is the sender-side component that prepares entities for commitment.

```
┌─────────────────────────────────────────────────┐
│              ENTITY ENGINE (v2)                    │
│                                                    │
│  ┌─────────────┐    ┌──────────────────┐          │
│  │   Content    │    │   Shape Analyzer  │          │
│  │   Ingester   │───▶│   (schema detect) │          │
│  └─────────────┘    └────────┬─────────┘          │
│                               │                     │
│                    ┌──────────▼─────────┐          │
│                    │  Identity Computer  │          │
│                    │  H(content||shape|| │          │
│                    │    time||pubkey)    │          │
│                    └──────────┬─────────┘          │
│                               │                     │
│                    ┌──────────▼─────────┐          │
│                    │  Erasure Encoder   │          │
│                    │  (n shards, k min) │          │
│                    └──────────┬─────────┘          │
│                               │ plaintext shards    │
│                    ┌──────────▼─────────┐          │
│                    │  ★ Shard Encryptor │ ◀─ NEW   │
│                    │  CEK = random(256) │          │
│                    │  AEAD(CEK, shard,  │          │
│                    │    nonce=index)    │          │
│                    └──────────┬─────────┘          │
│                               │ encrypted shards    │
│                    ┌──────────▼─────────┐          │
│                    │  Shard Distributor │          │
│                    │  (consistent hash) │          │
│                    └──────────┬─────────┘          │
│                               │                     │
│                    ┌──────────▼─────────┐          │
│                    │  Commitment Writer │          │
│                    │  (Merkle root only)│          │
│                    └────────────────────┘          │
└─────────────────────────────────────────────────┘
```

### 2. Lattice Key Generator (v2 — Minimal Sealed Key)

```
┌──────────────────────────────────────────────────────┐
│        LATTICE KEY GENERATOR (Option C)           │
│                                                        │
│  Inputs:                                               │
│  ├── entity_id (from commitment)                       │
│  ├── CEK (from shard encryption)            ◀─ NEW    │
│  ├── commitment_ref (hash of record)                   │
│  ├── receiver_pubkey (destination identity)             │
│  └── access_policy (rules for materialization)          │
│                                                        │
│  Inner Payload (3 secrets + policy):                   │
│  ┌─────────────────────────────────────────────┐      │
│  │ entity_id:      32 bytes (hash)              │      │
│  │ CEK:            32 bytes (symmetric key)     │ NEW  │
│  │ commitment_ref: 32 bytes (record hash)       │      │
│  │ access_policy:  ~20-50 bytes (rules)         │      │
│  │                                               │      │
│  │ REMOVED: shard_ids, encoding_params,          │      │
│  │          sender_id (all derivable from record)│      │
│  └─────────────────────────────────────────────┘      │
│  Inner size: ~160 bytes                                │
│                                                        │
│  Sealing (envelope encryption):                        │
│  1. Generate ephemeral ML-KEM encapsulation            │
│  2. Derive AEAD key from ML-KEM shared secret          │
│  3. AEAD encrypt entire inner payload                   │
│  4. Package: kem_ct(1088) + nonce + aead_ct + tag        │
│     PoC:  nonce=16B, tag=32B  (BLAKE2b-based AEAD)      │
│     Prod: nonce=24B, tag=16B  (XChaCha20-Poly1305)      │
│                                                        │
│  Forward Secrecy Lifecycle:                              │
│  • shared_secret used once, then zeroized                │
│  • Only holder of dk can recover ss from kem_ct          │
│  • Receivers SHOULD rotate ek/dk periodically            │
│                                                        │
│  Output:                                               │
│  └── Sealed LatticeKey (~1,300B opaque)             │
│      PoC overhead:  1088+16+32 = 1136B over inner   │
│      Prod overhead: 1088+24+16 = 1128B over inner   │
└──────────────────────────────────────────────────────┘
```

### 3. Materialization Engine (v2 — Unseal, Derive, Decrypt)

```
┌─────────────────────────────────────────────────────────────┐
│              MATERIALIZATION ENGINE (Option C)                │
│                                                               │
│  ┌────────────────┐   ┌──────────────────────┐              │
│  │ ★ Key Unsealer  │──▶│ Commitment Verifier   │              │
│  │ (unseal with    │   │ (fetch record,        │              │
│  │  private key,   │   │  verify H(record) ==  │              │
│  │  extract CEK)   │   │  commitment_ref)      │              │
│  └────────────────┘   └──────────┬───────────┘              │
│                                   │                           │
│                        ┌──────────▼───────────┐              │
│                        │  ★ Location Deriver   │  ◀─ NEW     │
│                        │  ConsistentHash(       │              │
│                        │    entity_id || index)  │              │
│                        │  (NO shard_ids needed) │              │
│                        └──────────┬───────────┘              │
│                                   │                           │
│                        ┌──────────▼───────────┐              │
│                        │  Parallel Fetcher     │              │
│                        │  (fetch k-of-n        │              │
│                        │   ENCRYPTED shards    │              │
│                        │   from nearest nodes)  │              │
│                        └──────────┬───────────┘              │
│                                   │                           │
│           ┌───────────────────────┼───────────────┐          │
│           ▼            ▼          ▼         ▼     ▼          │
│        [🔒 e1]    [🔒 e2]   [🔒 e3]  [🔒 e4]  ...         │
│           │            │          │         │                 │
│           └───────────────────────┼───────────────┘          │
│                                   │                           │
│                        ┌──────────▼───────────┐              │
│                        │  ★ Shard Decryptor    │  ◀─ NEW     │
│                        │  AEAD_Decrypt(CEK,    │              │
│                        │    enc_shard, index)  │              │
│                        │  (tag verified first) │              │
│                        └──────────┬───────────┘              │
│                                   │                           │
│                        ┌──────────▼───────────┐              │
│                        │  Erasure Decoder      │              │
│                        │  (reconstruct from    │              │
│                        │   k decrypted shards) │              │
│                        └──────────┬───────────┘              │
│                                   │                           │
│                        ┌──────────▼───────────┐              │
│                        │  Entity Verifier      │              │
│                        │  (H(entity) ==        │              │
│                        │   entity_id?)         │              │
│                        └──────────┬───────────┘              │
│                                   │                           │
│                                   ▼                           │
│                           ✓ ENTITY MATERIALIZED              │
└─────────────────────────────────────────────────────────────┘
```

---

## 4. Commitment Network Topology

```
                    ┌─────────────────────┐
                    │   COMMITMENT LOG    │
                    │   (Global, Shared,  │
                    │    Append-Only)     │
                    └────────┬────────────┘
                             │
              ┌──────────────┼──────────────┐
              │              │              │
         ┌────▼────┐   ┌────▼────┐   ┌────▼────┐
         │ Region  │   │ Region  │   │ Region  │
         │   A     │   │   B     │   │   C     │
         │(US-East)│   │(EU-West)│   │(AP-East)│
         └────┬────┘   └────┬────┘   └────┬────┘
              │              │              │
        ┌─────┼─────┐  ┌────┼────┐   ┌────┼────┐
        │     │     │  │    │    │   │    │    │
       ┌▼┐  ┌▼┐  ┌▼┐ ┌▼┐  ┌▼┐ ┌▼┐ ┌▼┐  ┌▼┐ ┌▼┐
       │N│  │N│  │N│ │N│  │N│ │N│ │N│  │N│ │N│
       │1│  │2│  │3│ │4│  │5│ │6│ │7│  │8│ │9│
       └─┘  └─┘  └─┘ └─┘  └─┘ └─┘ └─┘  └─┘ └─┘

       Commitment nodes store ENCRYPTED shards and
       replicate within and across regions. Receivers
       fetch from nearest nodes. Nodes cannot read
       shard content (ciphertext only).
```

### 4.1 Node Lifecycle

```
┌──────────────────────────────────────────────────────────┐
│                    NODE LIFECYCLE                          │
│                                                           │
│   ┌───────────┐    Identity      ┌───────────┐           │
│   │   Apply   │───attestation───▶│   Admit   │           │
│   │ (new node)│   + storage bond │ (verified) │           │
│   └───────────┘                  └─────┬─────┘           │
│                                        │                  │
│                                        ▼                  │
│                                 ┌────────────┐           │
│                            ┌───▶│   Active   │◀──┐       │
│                            │    │ (serving)  │   │       │
│                            │    └──────┬─────┘   │       │
│                            │           │         │       │
│                            │      Audit│challenge│Pass   │
│                            │           ▼         │       │
│                            │    ┌────────────┐   │       │
│                            │    │   Audit    │───┘       │
│                            │    │ (respond   │           │
│                            │    │  H(ct||n)) │           │
│                            │    └──────┬─────┘           │
│                            │           │                  │
│                            │      Fail │ (strike)        │
│                            │           ▼                  │
│                            │    ┌────────────┐           │
│                            │    │  Warning   │           │
│                            │    │ (1-2       │           │
│                            │    │  strikes)  │           │
│                            │    └──────┬─────┘           │
│                            │           │                  │
│                            Pass        │ 3rd strike       │
│                            │           ▼                  │
│                            │    ┌────────────┐           │
│                            └────│  Evicted   │           │
│                                 │ (bond slash│           │
│                                 │  + repair) │           │
│                                 └────────────┘           │
└──────────────────────────────────────────────────────────┘
```

### 4.2 Audit Protocol

```
 Auditor                     Node                    Other Replica
    │                          │                          │
    │  Challenge(eid, idx, n)  │                          │
    │─────────────────────────▶│                          │
    │                          │  Compute H(ct || nonce)  │
    │      H(ct || nonce)      │                          │
    │◀─────────────────────────│                          │
    │                          │                          │
    │  Verify against known-good hash                     │
    │  (fetched from another replica or cached)           │
    │──────────────────────────────────────────────────▶  │
    │                          │   H(ct || nonce)         │
    │◀─────────────────────────────────────────────────── │
    │                          │                          │
    │  Match? → PASS           │                          │
    │  Mismatch/Timeout → FAIL │                          │
```

---

## 5. Transfer Flow (Sequence)

```
 Sender                    Commitment Layer              Receiver
   │                             │                          │
   │  1. Compute EntityID        │                          │
   │  2. Erasure encode → shards │                          │
   │  3. Generate CEK (random)   │                          │
   │  4. AEAD encrypt each shard │                          │
   │  5. Distribute encrypted ──▶│                          │
   │     shards to nodes         │  (ciphertext stored on   │
   │                             │   nodes by (eid, index)) │
   │  6. Write commitment ──────▶│                          │
   │     record to log           │  (Merkle root only,      │
   │     (NO shard_ids)          │   no shard_ids)          │
   │                             │                          │
   │  7. Generate lattice       │                          │
   │     key (entity_id + CEK    │                          │
   │     + ref + policy)         │                          │
   │  8. Seal key to receiver ──────────────────────────▶  │
   │     (~1,300 bytes, ML-KEM)  │                          │
   │                             │                          │
   │  ✓ Sender done.             │          9. Unseal key   │
   │    Can go offline.          │             (private key) │
   │                             │         10. Extract CEK   │
   │                             │◀──────  11. Fetch record  │
   │                             │         12. Verify record │
   │                             │                          │
   │                             │         13. Derive shard  │
   │                             │             locations     │
   │                             │◀──────  14. Fetch k       │
   │                             │──────▶      encrypted     │
   │                             │             shards        │
   │                             │                          │
   │                             │         15. AEAD decrypt  │
   │                             │             with CEK      │
   │                             │         16. Erasure decode│
   │                             │         17. Verify entity │
   │                             │                          │
   │                             │         ✓ ENTITY          │
   │                             │           MATERIALIZED    │
```

---

## 6. Security Layers

```
┌──────────────────────────────────────────────────┐
│              SECURITY STACK (v2)                    │
│                                                    │
│  Layer 6: ACCESS POLICY                            │
│  ├── One-time materialization                      │
│  ├── Time-bounded access                           │
│  ├── Delegatable permissions                       │
│  └── Revocable lattice link                        │
│                                                    │
│  Layer 5: SEALED ENVELOPE (ML-KEM-768)                 │
│  ├── Entire key encapsulated via ML-KEM-768 (FIPS 203)   │
│  ├── Fresh encapsulation per seal (forward secrecy)      │
│  ├── Zero metadata leakage on interception               │
│  └── Receiver identity (dk) verified during unseal        │
│                                                    │
│  Layer 4: SHARD ENCRYPTION (NEW)                   │
│  ├── AEAD encryption with random 256-bit CEK       │
│  ├── Per-shard nonce (shard_index)                 │
│  ├── Nodes store ciphertext only (can't read)      │
│  ├── Authenticated: tampering detected before use  │
│  └── CEK exists only inside sealed lattice key│
│                                                    │
│  Layer 3: ZERO-KNOWLEDGE (Optional)                │
│  ├── ZK-proofs on commitment records               │
│  └── Verifiable computation on hidden data         │
│                                                    │
│  Layer 2: CRYPTOGRAPHIC INTEGRITY (Post-Quantum)       │
│  ├── Content-addressed entities (BLAKE3)              │
│  ├── Merkle root over encrypted shard hashes           │
│  ├── ML-DSA-65 signatures on commitments (FIPS 204)    │
│  └── AEAD tags on each shard (PoC: 32B / prod: 16B)    │
│                                                    │
│  Layer 1: INFORMATION-THEORETIC SECURITY           │
│  ├── Erasure coding (k-of-n threshold)             │
│  ├── < k shards (even decrypted) reveal nothing    │
│  └── Distributed across independent nodes          │
│                                                    │
└──────────────────────────────────────────────────┘
```

### Attack Surface Closure (v1 → v2)

```
  LEAK 1: Lattice Key (in transit)
  v1: ✗ Plaintext JSON with shard_ids, encoding params, sender_id
  v2: ✓ Sealed envelope — opaque ciphertext, zero metadata

  LEAK 2: Commitment Log (at rest)
  v1: ✗ Listed all shard_ids in plaintext
  v2: ✓ Merkle root only — hashes of ciphertext, no individual IDs

  LEAK 3: Commitment Nodes (at rest)
  v1: ✗ Stored plaintext shards, served to anyone
  v2: ✓ AEAD-encrypted ciphertext — useless without CEK
```

---

## 7. Data Flow Summary

| Stage | Data Size | Who Performs | Network Cost |
|-------|-----------|-------------|-------------|
| Entity → Shards | O(entity) | Sender (local) | None |
| Shards → Encrypted Shards | O(entity) + O(n×32) tags | Sender (local) | None |
| Encrypted Shards → Nodes | O(entity × replication) | Sender → Network | Amortized, async |
| Commitment Record | O(1) ~512B | Sender → Log | Minimal |
| **Lattice Key** | **O(1) ~1,300B sealed** | **Sender → Receiver** | **Near zero** |
| Encrypted Shards → Receiver | O(entity) | Network → Receiver | Local fetches |
| Decrypt + Decode | O(entity) | Receiver (local) | None |

**Critical insight**: The sender-to-receiver direct path carries O(1) data. The O(entity)
work happens between sender↔network (commit phase) and network↔receiver (materialize phase),
where "network" means **nearby commitment nodes**.

**Honest cost accounting**: Total system bandwidth is O(entity × replication_factor) + O(entity),
which is strictly greater than direct transfer's O(entity). The advantage is *not* bandwidth
reduction — it is bottleneck relocation: replacing one long-haul O(entity) transfer with
parallel local O(entity/k) fetches, plus amortized fan-out to multiple receivers.

---

## 8. Technology Choices

| Component | Recommended | Rationale |
|-----------|------------|-----------|
| Hash function | BLAKE3 | Fast, secure, parallelizable, ZK-friendly |
| Signatures | ML-DSA-65 (FIPS 204) | Post-quantum (Dilithium); NIST Level 3 |
| Key encapsulation | ML-KEM-768 (FIPS 203) | Post-quantum (Kyber); replaces X25519 |
| Erasure coding | Vandermonde RS over GF(256) | Any k-of-n reconstruction (polynomial 0x11D) |
| Commitment log | Merkle DAG / append-only ledger | Immutable, verifiable, decentralizable |
| Shard placement | Consistent hashing (jump hash) | Deterministic, balanced, minimal disruption |
| Shard encryption | XChaCha20-Poly1305 | AEAD, fast, nonce-misuse resistant |
| Storage proofs | Challenge-response (H(ct ‖ nonce)) | Lightweight, no SNARKs/VDFs needed |
| Node identity | ML-DSA-65 attestation / SPIFFE SVID | Sybil resistance via verifiable identity |
