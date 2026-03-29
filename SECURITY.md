# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in the Entanglement Transfer Protocol,
please report it responsibly.

**Email:** security@suwappu.bot

Please include:
- Description of the vulnerability
- Steps to reproduce
- Potential impact assessment
- Suggested fix (if any)

We will acknowledge receipt within 48 hours and provide a detailed response
within 7 days.

## Scope

### In Scope

- **Cryptographic vulnerabilities** — weaknesses in the PoC implementations of
  ML-KEM, ML-DSA, AEAD, erasure coding, or hashing
- **Key management flaws** — CEK leakage, lattice key exposure, inadequate
  key zeroization
- **Shard exposure** — any path that allows reconstruction of entity content
  without possessing the sealed lattice key
- **Commitment integrity** — attacks on the append-only log, Merkle tree
  manipulation, signature forgery
- **Access control bypass** — materializing entities without proper authorization
- **Replay attacks** — circumventing nonce-based replay protection in the bridge

### Out of Scope

- **PoC simulation limits** — the current implementation uses BLAKE2b-based
  simulations for ML-KEM/ML-DSA. Known PoC limitations (documented in
  `CODE_IMPROVEMENTS.md`) are not vulnerabilities.
- **Denial of service on local instances** — the PoC runs in-memory with no
  network exposure
- **Dependencies** — vulnerabilities in Python stdlib modules should be reported
  to the Python Security Response Team

## Security Documentation

For detailed security analysis and design decisions:

- [Security Review (2026-02-24)](docs/design-decisions/Security/SECURITY_REVIEW-2-24-2026.md)
- [Lattice Key Shard Exposure Analysis](docs/design-decisions/Security/001-lattice-key-shard-exposure.md)
- [Architecture — Security Layers](docs/design-decisions/ARCHITECTURE.md#6-security-layers)

## ZK Mode Warning

ZK Transfer Mode uses Groth16 over BLS12-381, which is **not post-quantum safe**.
Deployments with a quantum-adversary threat model must use standard mode only.
See [ZK_TRANSFER_MODE.md](docs/design-decisions/ZK_TRANSFER_MODE.md) for details.

## Disclosure Policy

- We follow coordinated disclosure
- Security fixes will be released as patch versions
- Critical vulnerabilities will be disclosed publicly after a fix is available
