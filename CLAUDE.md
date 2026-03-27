# CLAUDE.md

## Project Overview

Entanglement Transfer Protocol (ETP) — a post-quantum secure data transfer system built on the Lattice Transfer Protocol (LTP). Authored by Javier Calderon Jr, CTO of Global Settlement (GSX).

## Key Commands

```bash
# Python tests (from project root)
pip install -e ".[dev]"
pytest tests/ -v

# Solidity tests (from contracts/)
cd contracts && forge test -vvv

# Deploy to GSX Testnet (from contracts/)
source .env
forge script script/DeployTestnet.s.sol:DeployTestnet \
    --rpc-url "$GSX_RPC_URL" \
    --private-key "$GSX_DEPLOYER_KEY" \
    --broadcast --chain-id 103115120 -vvvv

# Verify deployed contract state
cast call <PROXY_ADDRESS> "version()(uint256)" --rpc-url "$GSX_RPC_URL"
cast call <PROXY_ADDRESS> "admin()(address)" --rpc-url "$GSX_RPC_URL"
```

## Architecture

- **Python source:** `src/ltp/` — 60 modules, 8 subpackages
- **Contracts:** `contracts/src/` — LTPAnchorRegistry (UUPS), LTPMultiSig, ILTPAnchorRegistry
- **Tests:** `tests/` (1,167 Python) + `contracts/test/` (84 Solidity)
- **Deploy scripts:** `contracts/script/` — Deploy.s.sol, DeployTestnet.s.sol, DeployMainnet.s.sol, UpgradeV4.s.sol

## Current Deployment (v5)

Chain: GSX Testnet (ID `103115120`)

- Proxy: `0xB29d8BFF4973D1D7bcB10E32112EBB8fdd530bF4`
- Implementation: `0xADf01df5B6Bef8e37d253571ab6e21177aCb7796`
- MultiSig: `0x0106A79e9236009a05742B3fB1e3B7a52F44373D`
- Timelock: `0x7C2665F7e68FE635ee8F10aa0130AEBC603a9Db8`

Governance: MultiSig (2-of-2) → Timelock (60s) → Registry

## Conventions

- **Solidity:** 0.8.24, optimizer 200 runs, via-IR, Cancun EVM, OpenZeppelin for proxy/timelock
- **Python:** 3.12+, pytest + Hypothesis for property-based testing
- **Hashing:** SHA3-256 for all on-chain/canonical paths, BLAKE3-256 for internal only — never mix lanes
- **Crypto:** Real PQC only — ML-KEM-768 (FIPS 203), ML-DSA-65 (FIPS 204), XChaCha20-Poly1305. No simulations.
- **Contract versioning:** Bump `version()` in LTPAnchorRegistry.sol and update test assertions when deploying new versions
- **Post-deploy:** Always verify on-chain state (version, admin, paused, threshold, minDelay, EIP-1967 slot)

## Important Files

- `LTP_COMPREHENSIVE_REPORT.md` — Full 13-section technical report
- `contracts/.env` — Deployment keys and addresses (gitignored, contains secrets)
- `contracts/.gitignore` — Ensures .env, broadcast/, cache/ are excluded
- `tests/conftest.py` — Session-scoped PQ keypair fixtures (alice, bob, eve)

## Things to Know

- The Python state machine has 10 valid transitions; Solidity has 11 (adds UNKNOWN→ANCHORED). This is intentional and formally verified in `CrossParityTest`.
- Contract admin is always the Timelock, never the deployer or MultiSig directly.
- `contracts/broadcast/` contains deployment transaction logs — gitignored but useful for history.
- The `.env` file has Windows line endings (`\r\n`) — source it with care in zsh.
