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

## Artifact boundary validation

The snarkjs import methods accept unknown input and return stable INVALID_SNARKJS_PROOF / INVALID_SNARKJS_VK errors for malformed artifacts. If protocol or curve metadata is present it must identify groth16 and bn128/bn254. Legacy artifacts omitting those optional fields remain supported. A present nPublic must be a safe integer matching IC.length - 1.

Point coordinates must be non-negative bigint values, safe integer numbers, or nonempty decimal/hex strings strictly below the BN254 base-field modulus. Booleans, null, blank strings and unsafe numeric coercion are rejected. G1 arrays accept [x,y] or [x,y,1]; G2 arrays accept [x,y] or [x,y,[1,0]]. Non-affine/projective representations are rejected rather than silently dropping Z. Curve membership and subgroup checks still execute in the engine during verification.

Calldata keeps its EIP-197 G2 component order and requires exact coordinate tuple shapes. Genuine proof and calldata interoperability tests remain part of npm test. This parser change is not independent security approval or a production certification.
