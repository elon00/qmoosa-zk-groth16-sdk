import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { Groth16Client, BN254_FIELD_MODULUS_Q } from '../dist/index.js';
const load = name => JSON.parse(fs.readFileSync(new URL('./fixtures/groth16/' + name, import.meta.url), 'utf8'));
const client = new Groth16Client();
const proof = () => load('proof.json');
const key = () => load('verification_key.json');
const inputs = load('public.json');
const proofError = /INVALID_SNARKJS_PROOF/;
const keyError = /INVALID_SNARKJS_VK/;

for (const [artifact, property, value] of [
  ['proof', 'protocol', 'plonk'], ['proof', 'curve', 'bls12381'],
  ['key', 'protocol', 'plonk'], ['key', 'curve', 'bls12381']
]) {
  test('rejects conflicting ' + artifact + ' ' + property + ' metadata', () => {
    const raw = artifact === 'proof' ? proof() : key(); raw[property] = value;
    assert.throws(() => artifact === 'proof' ? client.parseSnarkJsProof(raw) : client.parseSnarkJsVk(raw), artifact === 'proof' ? proofError : keyError);
  });
}
test('legacy artifacts without optional metadata remain interoperable', () => {
  const rawProof = proof(); const rawKey = key();
  for (const raw of [rawProof, rawKey]) { delete raw.protocol; delete raw.curve; }
  assert.equal(client.verify(client.parseSnarkJsVk(rawKey), client.parseSnarkJsProof(rawProof), inputs), true);
});
test('affine point arrays without projective markers remain interoperable', () => {
  const rawProof = proof(); const rawKey = key();
  for (const name of ['pi_a', 'pi_b', 'pi_c']) rawProof[name] = rawProof[name].slice(0, 2);
  for (const name of ['vk_alpha_1', 'vk_beta_2', 'vk_gamma_2', 'vk_delta_2']) rawKey[name] = rawKey[name].slice(0, 2);
  rawKey.IC = rawKey.IC.map(point => point.slice(0, 2));
  assert.equal(client.verify(client.parseSnarkJsVk(rawKey), client.parseSnarkJsProof(rawProof), inputs), true);
});
for (const [label, mutate] of [
  ['non-affine G1 marker', raw => { raw.pi_a[2] = '2'; }],
  ['non-affine G2 marker', raw => { raw.pi_b[2] = ['0', '1']; }],
  ['ignored extra G1 coordinate', raw => { raw.pi_a.push('7'); }],
  ['wrong G2 nesting', raw => { raw.pi_b[0] = '12'; }]
]) {
  test('rejects ' + label + ' in a genuine proof artifact', () => {
    const raw = proof(); mutate(raw);
    assert.throws(() => client.parseSnarkJsProof(raw), proofError);
  });
}
for (const [label, value] of [
  ['boolean', true], ['null', null], ['blank', ' '], ['unsafe number', Number.MAX_SAFE_INTEGER + 1],
  ['base-field modulus', BN254_FIELD_MODULUS_Q.toString()], ['negative', -1], ['object', {}], ['fractional string', '1.5']
]) {
  test('rejects ' + label + ' point coordinates with a stable artifact error', () => {
    const raw = proof(); raw.pi_a[0] = value;
    assert.throws(() => client.parseSnarkJsProof(raw), proofError);
  });
}
for (const value of [null, [], 'proof']) {
  test('rejects invalid artifact root ' + JSON.stringify(value), () => {
    assert.throws(() => client.parseSnarkJsProof(value), proofError);
    assert.throws(() => client.parseSnarkJsVk(value), keyError);
  });
}
for (const [label, mutate] of [
  ['empty IC', raw => { raw.IC = []; }],
  ['non-array IC', raw => { raw.IC = {}; }],
  ['malformed IC point', raw => { raw.IC[0] = []; }],
  ['non-affine IC marker', raw => { raw.IC[0][2] = '0'; }],
  ['nPublic mismatch', raw => { raw.nPublic += 1; }],
  ['non-integer nPublic', raw => { raw.nPublic = 1.5; }],
  ['string nPublic', raw => { raw.nPublic = '2'; }]
]) {
  test('rejects verification key with ' + label, () => {
    const raw = key(); mutate(raw);
    assert.throws(() => client.parseSnarkJsVk(raw), keyError);
  });
}
for (const [label, mutate] of [
  ['boolean coordinate', data => { data.a[0] = true; }],
  ['extra coordinate', data => { data.c.push('1'); }],
  ['malformed nesting', data => { data.b[0] = '12'; }]
]) {
  test('rejects calldata ' + label + ' with a stable boundary error', () => {
    const data = client.exportCalldata(client.parseSnarkJsProof(proof()), inputs); mutate(data);
    assert.throws(() => client.verifyCalldata(client.parseSnarkJsVk(key()), data), /INVALID_GROTH16_CALLDATA/);
  });
}
