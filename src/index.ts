/**
 * QMOOSA Zero-Knowledge Cryptography — Groth16 Client SDK
 *
 * High-level client API for verifying Groth16 ZK-SNARK proofs, converting
 * proofs to EVM calldata, and parsing snarkjs / Circom artifacts.
 */

import {
  proofToCalldata,
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
    // Calldata G2 ordering per EIP-197 is: b[0] = [X1, X0], b[1] = [Y1, Y0]
    const proof: Groth16Proof = {
      a: {
        x: BigInt(calldata.a[0]),
        y: BigInt(calldata.a[1])
      },
      b: {
        x: [BigInt(calldata.b[0][1]), BigInt(calldata.b[0][0])],
        y: [BigInt(calldata.b[1][1]), BigInt(calldata.b[1][0])]
      },
      c: {
        x: BigInt(calldata.c[0]),
        y: BigInt(calldata.c[1])
      }
    };

    const inputs = calldata.input.map(s => BigInt(s));
    return this.engine.verifyProof(vk, proof, inputs);
  }

  /**
   * Parses snarkjs proof.json format into a canonical Groth16Proof.
   */
  public parseSnarkJsProof(json: any): Groth16Proof {
    if (!json.pi_a || !json.pi_b || !json.pi_c) {
      throw new Error('INVALID_SNARKJS_PROOF: Missing pi_a, pi_b, or pi_c');
    }

    return {
      a: {
        x: BigInt(json.pi_a[0]),
        y: BigInt(json.pi_a[1])
      },
      b: {
        // snarkjs pi_b format is [[X0, X1], [Y0, Y1], ...]
        x: [BigInt(json.pi_b[0][0]), BigInt(json.pi_b[0][1])],
        y: [BigInt(json.pi_b[1][0]), BigInt(json.pi_b[1][1])]
      },
      c: {
        x: BigInt(json.pi_c[0]),
        y: BigInt(json.pi_c[1])
      }
    };
  }

  /**
   * Parses snarkjs verification_key.json into a canonical Groth16VerifyingKey.
   */
  public parseSnarkJsVk(json: any): Groth16VerifyingKey {
    if (!json.vk_alpha_1 || !json.vk_beta_2 || !json.vk_gamma_2 || !json.vk_delta_2 || !json.IC) {
      throw new Error('INVALID_SNARKJS_VK: Missing required key parameters');
    }

    return {
      alpha1: {
        x: BigInt(json.vk_alpha_1[0]),
        y: BigInt(json.vk_alpha_1[1])
      },
      beta2: {
        x: [BigInt(json.vk_beta_2[0][0]), BigInt(json.vk_beta_2[0][1])],
        y: [BigInt(json.vk_beta_2[1][0]), BigInt(json.vk_beta_2[1][1])]
      },
      gamma2: {
        x: [BigInt(json.vk_gamma_2[0][0]), BigInt(json.vk_gamma_2[0][1])],
        y: [BigInt(json.vk_gamma_2[1][0]), BigInt(json.vk_gamma_2[1][1])]
      },
      delta2: {
        x: [BigInt(json.vk_delta_2[0][0]), BigInt(json.vk_delta_2[0][1])],
        y: [BigInt(json.vk_delta_2[1][0]), BigInt(json.vk_delta_2[1][1])]
      },
      ic: json.IC.map((pt: any) => ({
        x: BigInt(pt[0]),
        y: BigInt(pt[1])
      }))
    };
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
