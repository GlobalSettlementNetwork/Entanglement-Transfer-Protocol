# Documentation Index

## Overview

The Entanglement Transfer Protocol documentation is organized into five categories.

| Category | Document | Description |
|----------|----------|-------------|
| **Specification** | [Whitepaper](WHITEPAPER.md) | Full protocol design — three-phase COMMIT/LATTICE/MATERIALIZE |
| **Architecture** | [Architecture](design-decisions/ARCHITECTURE.md) | System components, data flow, security layers |
| | [Commitment Network Options](design-decisions/COMMITMENT_NETWORK_OPTIONS.md) | Custom L1 vs Ethereum L1/L2 analysis |
| | [Streaming Protocol](design-decisions/STREAMING_PROTOCOL.md) | Chunked streaming, bandwidth amortization, backpressure |
| | [Enforcement Mechanisms](design-decisions/ENFORCEMENT_MECHANISMS.md) | PDP proofs, programmable slashing, progressive decentralization |
| | [Cross-Deployment Federation](design-decisions/CROSS_DEPLOYMENT_FEDERATION.md) | Network discovery, trust levels, cross-network materialization |
| | [ZK Transfer Mode](design-decisions/ZK_TRANSFER_MODE.md) | Hiding commitments, Groth16 proofs, post-quantum upgrade path |
| **Operations** | [Production Plan](PRODUCTION_PLAN.md) | PoC to production roadmap — 7 phases, 14 weeks |
| | [Deployment Guide](DEPLOYMENT_GUIDE.md) | Docker, Kubernetes, CI/CD, key management, monitoring |
| | [Bridge MVP](bridge-mvp-scope.md) | L1-L2 cross-chain bridge scope and components |
| **Security** | [Security Review](design-decisions/Security/SECURITY_REVIEW-2-24-2026.md) | Formal security review (2026-02-24) |
| | [Shard Exposure Analysis](design-decisions/Security/001-lattice-key-shard-exposure.md) | Attack chain analysis and Option A-D comparison |
| **Reviews** | [Review #1](design-decisions/Reviews/001/001-Formal-Whitepaper-Review.md) | Formal whitepaper review |
| | [Review #2](design-decisions/Reviews/002/002-Formal-Whitepaper-Review.md) | Formal whitepaper review |
| | [Review #3](design-decisions/Reviews/003/003-Formal-Whitepaper-review.md) | Formal whitepaper review |
| | [Eastern Research Landscape](design-decisions/Reviews/004/004-Eastern-Research-Landscape.md) | Asian blockchain research landscape for ETP expansion |

## Document Relationships

```mermaid
flowchart TD
    WP[Whitepaper] --> ARCH[Architecture]
    WP --> PP[Production Plan]
    WP --> ZK[ZK Transfer Mode]
    WP --> FED[Federation]
    WP --> ENF[Enforcement]
    WP --> STR[Streaming]

    ARCH --> CNO[Commitment Network Options]
    ARCH --> SEC[Security Review]
    ARCH --> SHARD[Shard Exposure Analysis]

    PP --> DG[Deployment Guide]
    PP --> BRIDGE[Bridge MVP]

    CNO --> DG

    SEC --> SHARD

    R1[Review #1] -.-> WP
    R2[Review #2] -.-> WP
    R3[Review #3] -.-> WP
    R4[Eastern Research] -.-> WP
```

## Quick Start

New to ETP? Read in this order:

1. **[Whitepaper](WHITEPAPER.md)** — Understand the core protocol
2. **[Architecture](design-decisions/ARCHITECTURE.md)** — See how it's built
3. **[Security Review](design-decisions/Security/SECURITY_REVIEW-2-24-2026.md)** — Understand the threat model
4. **[Production Plan](PRODUCTION_PLAN.md)** — See the path to production
