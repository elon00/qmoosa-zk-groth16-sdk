# QMOOSA Zero-Knowledge Cryptography — Groth16 Client SDK

Developer SDK for verifying Groth16 zero-knowledge proofs, formatting EVM calldata for on-chain smart contract settlement, and parsing snarkjs / Circom artifacts.

## Security Governance
- **Zero Cloud Spend Invariant**: $0.00 spent across all cloud and blockchain resources.
- **Production Certification Lock**: Mainnet/public testnets strictly locked at `0 / 1,000 CERTIFIED`.

## Build & Test
```bash
npm install
npm run build
npm test
npm run lint
```

## Public input validation and genuine-proof tests

Blank strings are rejected instead of being coerced to zero. Explicit zero (0, 0n, "0", "0x0") and trimmed nonempty strings remain supported. Verification and calldata export share this validation.

The added suite imports real snarkjs Groth16 proof/key artifacts, verifies normal and zero public inputs, rejects changed inputs, and verifies an exported calldata round trip. Fixture provenance is in tests/fixtures/groth16/provenance.json. Setup keys are test-only. CI pins the tested engine development commit 001b1ee757fa19f47eccb7f7e4c573c77cd4c668 from engine PR #1; normal review/integration and independent security review remain separate. Calldata round trips do not constitute an on-chain deployment.
