import test from 'node:test';
import assert from 'node:assert/strict';
import {
  Groth16Client,
  Groth16Engine
} from '../dist/index.js';

test('Groth16 SDK: High-Level Client Verification with Multi-Type Inputs', () => {
  const engine = new Groth16Engine();
  const client = new Groth16Client(engine);
  const { vk, proof } = engine.generateMockCircuit(3, [111n, 222n, 333n]);

  // Mixed input types: bigint, string, number
  const mixedInputs = [111n, '222', 333];
  const isValid = client.verify(vk, proof, mixedInputs);
  assert.equal(isValid, true, 'Mixed input types must verify successfully');
});

test('Groth16 SDK: EVM Calldata Generation & Calldata Verification Round-Trip', () => {
  const engine = new Groth16Engine();
  const client = new Groth16Client(engine);
  const { vk, proof, publicInputs } = engine.generateMockCircuit(2, [555n, 666n]);

  const calldata = client.exportCalldata(proof, publicInputs);
  assert.equal(calldata.a.length, 2);
  assert.equal(calldata.b.length, 2);
  assert.equal(calldata.c.length, 2);
  assert.equal(calldata.input.length, 2);

  const isValidCalldata = client.verifyCalldata(vk, calldata);
  assert.equal(isValidCalldata, true, 'Exported calldata must verify via verifyCalldata()');
});

test('Groth16 SDK: SnarkJs Artifact Format Parsing', () => {
  const client = new Groth16Client();

  const mockSnarkJsProof = {
    pi_a: ['10', '20', '1'],
    pi_b: [
      ['30', '40'],
      ['50', '60'],
      ['1', '0']
    ],
    pi_c: ['70', '80', '1'],
    protocol: 'groth16',
    curve: 'bn128'
  };

  const parsedProof = client.parseSnarkJsProof(mockSnarkJsProof);
  assert.equal(parsedProof.a.x, 10n);
  assert.equal(parsedProof.a.y, 20n);
  assert.equal(parsedProof.b.x[0], 30n);
  assert.equal(parsedProof.b.x[1], 40n);
  assert.equal(parsedProof.c.x, 70n);
});

test('Groth16 SDK: Adversarial Negative Control - Tampered String Input Rejection', () => {
  const engine = new Groth16Engine();
  const client = new Groth16Client(engine);
  const { vk, proof } = engine.generateMockCircuit(2, [100n, 200n]);

  const forgedInputs = ['100', '201'];
  const isValid = client.verify(vk, proof, forgedInputs);
  assert.equal(isValid, false, 'Tampered string input must fail verification');
});

test('Groth16 SDK: Adversarial Negative Control - Invalid Input Type Throws', () => {
  const client = new Groth16Client();
  const engine = new Groth16Engine();
  const { vk, proof } = engine.generateMockCircuit(2);

  assert.throws(
    () => client.verify(vk, proof, [{}, null]),
    /UNSUPPORTED_SCALAR_TYPE/
  );
});
