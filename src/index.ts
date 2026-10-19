/**
 * QMOOSA Zero-Knowledge Cryptography — Groth16 Client SDK
 *
 * High-level client API for verifying Groth16 ZK-SNARK proofs, converting
 * proofs to EVM calldata, and parsing snarkjs / Circom artifacts.
 */

import {
  proofToCalldata,
  BN254_FIELD_MODULUS_Q,
  validateScalarFieldElement,
  type G1Point,
  type G2Point,
  type Groth16Calldata,
  type Groth16Proof,
  type Groth16VerifyingKey
} from '@qmoosa/zk-groth16-protocol';
import { Groth16Engine } from '@qmoosa/zk-groth16-engine';

export * from '@qmoosa/zk-groth16-protocol';
export * from '@qmoosa/zk-groth16-engine';

type Artifact = Record<string, unknown>;

function invalidArtifact(prefix: string, message: string): never {
  throw new Error(prefix + ': ' + message);
}
function readArtifact(value: unknown, prefix: string): Artifact {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    invalidArtifact(prefix, 'Expected an artifact object');
  }
  const artifact = value as Artifact;
  if (artifact.protocol !== undefined && artifact.protocol !== 'groth16') {
    invalidArtifact(prefix, 'Unsupported protocol');
  }
  if (artifact.curve !== undefined && artifact.curve !== 'bn128' && artifact.curve !== 'bn254') {
    invalidArtifact(prefix, 'Unsupported curve');
  }
  return artifact;
}
function readArray(value: unknown, lengths: readonly number[], prefix: string, label: string): unknown[] {
  if (!Array.isArray(value) || !lengths.includes(value.length)) {
    invalidArtifact(prefix, label + ' has an invalid coordinate shape');
  }
  return value;
}
function readCoordinate(value: unknown, prefix: string): bigint {
  let coordinate: bigint;
  if (typeof value === 'bigint') coordinate = value;
  else if (typeof value === 'number' && Number.isSafeInteger(value) && value >= 0) coordinate = BigInt(value);
  else if (typeof value === 'string' && /^(?:[0-9]+|0[xX][0-9a-fA-F]+)$/.test(value.trim())) coordinate = BigInt(value.trim());
  else invalidArtifact(prefix, 'Coordinates must be non-negative integers without coercion');
  if (coordinate < 0n || coordinate >= BN254_FIELD_MODULUS_Q) {
    invalidArtifact(prefix, 'Coordinate exceeds the BN254 base field');
  }
  return coordinate;
}
function readG1(value: unknown, prefix: string, label: string, allowMarker = true): G1Point {
  const point = readArray(value, allowMarker ? [2, 3] : [2], prefix, label);
  if (point.length === 3 && readCoordinate(point[2], prefix) !== 1n) {
    invalidArtifact(prefix, label + ' must use affine coordinates with Z=1');
  }
  return { x: readCoordinate(point[0], prefix), y: readCoordinate(point[1], prefix) };
}
function readG2(value: unknown, prefix: string, label: string, allowMarker = true): G2Point {
  const point = readArray(value, allowMarker ? [2, 3] : [2], prefix, label);
  const x = readArray(point[0], [2], prefix, label + '.x');
  const y = readArray(point[1], [2], prefix, label + '.y');
  if (point.length === 3) {
    const z = readArray(point[2], [2], prefix, label + '.z');
    if (readCoordinate(z[0], prefix) !== 1n || readCoordinate(z[1], prefix) !== 0n) {
      invalidArtifact(prefix, label + ' must use affine coordinates with Z=[1,0]');
    }
  }
  return { x: [readCoordinate(x[0], prefix), readCoordinate(x[1], prefix)],
    y: [readCoordinate(y[0], prefix), readCoordinate(y[1], prefix)] };
}

export class Groth16Client {
  private readonly engine: Groth16Engine;

  constructor(engine?: Groth16Engine) {
    this.engine = engine ?? new Groth16Engine();
  }

  /**
   * Verifies a Groth16 proof against a verifying key and public inputs.
   * Public inputs can be bigints, decimal strings, hex strings (0x...), or numbers.
   */
  public verify(
    vk: Groth16VerifyingKey,
    proof: Groth16Proof,
    publicInputs: readonly (bigint | string | number)[]
  ): boolean {
    const parsedInputs = publicInputs.map(Groth16Client.parseScalar);
    return this.engine.verifyProof(vk, proof, parsedInputs);
  }

  /**
   * Exports a proof and public inputs to standard Ethereum calldata.
   */
  public exportCalldata(
    proof: Groth16Proof,
    publicInputs: readonly (bigint | string | number)[]
  ): Groth16Calldata {
    const parsedInputs = publicInputs.map(Groth16Client.parseScalar);
    return proofToCalldata(proof, parsedInputs);
  }

  /**
   * Verifies an EVM calldata payload against a verifying key.
   */
  public verifyCalldata(
    vk: Groth16VerifyingKey,
    calldata: Groth16Calldata
  ): boolean {
    const prefix = 'INVALID_GROTH16_CALLDATA';
    if (!calldata || typeof calldata !== 'object' || !Array.isArray(calldata.input)) {
      invalidArtifact(prefix, 'Expected calldata with a public input array');
    }
    const a = readG1(calldata.a, prefix, 'a', false);
    const b = readG2(calldata.b, prefix, 'b', false);
    const c = readG1(calldata.c, prefix, 'c', false);
    // EIP-197 calldata uses [c1,c0]; the engine uses [c0,c1].
    const proof: Groth16Proof = { a, b: { x: [b.x[1], b.x[0]], y: [b.y[1], b.y[0]] }, c };

    const inputs = calldata.input.map(Groth16Client.parseScalar);
    return this.engine.verifyProof(vk, proof, inputs);
  }

  /**
   * Parses snarkjs proof.json format into a canonical Groth16Proof.
   */
  public parseSnarkJsProof(json: unknown): Groth16Proof {
    const prefix = 'INVALID_SNARKJS_PROOF';
    const artifact = readArtifact(json, prefix);
    return { a: readG1(artifact.pi_a, prefix, 'pi_a'),
      b: readG2(artifact.pi_b, prefix, 'pi_b'), c: readG1(artifact.pi_c, prefix, 'pi_c') };
  }

  /** Parses an affine snarkjs BN254 Groth16 verification key. */
  public parseSnarkJsVk(json: unknown): Groth16VerifyingKey {
    const prefix = 'INVALID_SNARKJS_VK';
    const artifact = readArtifact(json, prefix);
    if (!Array.isArray(artifact.IC) || artifact.IC.length === 0) {
      invalidArtifact(prefix, 'IC must be a nonempty point array');
    }
    const ic = Array.from(artifact.IC, (point, index) => readG1(point, prefix, 'IC[' + index + ']'));
    if (artifact.nPublic !== undefined &&
        (typeof artifact.nPublic !== 'number' || !Number.isSafeInteger(artifact.nPublic) || artifact.nPublic < 0 || artifact.nPublic !== ic.length - 1)) {
      invalidArtifact(prefix, 'nPublic must match the IC public input count');
    }
    return { alpha1: readG1(artifact.vk_alpha_1, prefix, 'vk_alpha_1'),
      beta2: readG2(artifact.vk_beta_2, prefix, 'vk_beta_2'),
      gamma2: readG2(artifact.vk_gamma_2, prefix, 'vk_gamma_2'),
      delta2: readG2(artifact.vk_delta_2, prefix, 'vk_delta_2'), ic };
  }

  private static parseScalar(val: bigint | string | number): bigint {
    let scalar: bigint;
    if (typeof val === 'bigint') {
      scalar = val;
    } else if (typeof val === 'string') {
      const trimmed = val.trim();
      if (trimmed.length === 0) {
        throw new Error('INVALID_STRING_SCALAR: Public input must not be blank');
      }
      scalar = BigInt(trimmed);
    } else if (typeof val === 'number') {
      if (!Number.isSafeInteger(val) || val < 0) {
        throw new Error(`INVALID_NUMERIC_SCALAR: ${val} must be non-negative safe integer`);
      }
      scalar = BigInt(val);
    } else {
      throw new Error(`UNSUPPORTED_SCALAR_TYPE: ${typeof val}`);
    }

    validateScalarFieldElement(scalar);
    return scalar;
  }
}
