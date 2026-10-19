import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { Groth16Client } from '../dist/index.js';
const load = name => JSON.parse(fs.readFileSync(new URL('./fixtures/groth16/' + name, import.meta.url), 'utf8'));
const client = new Groth16Client();
const vk = client.parseSnarkJsVk(load('verification_key.json'));
for (const suffix of ['', '-zero']) {
  test('genuine snarkjs artifact verification and calldata round trip' + suffix, () => {
    const proof = client.parseSnarkJsProof(load('proof' + suffix + '.json'));
    const inputs = load('public' + suffix + '.json');
    assert.equal(client.verify(vk, proof, inputs), true);
    assert.equal(client.verifyCalldata(vk, client.exportCalldata(proof, inputs)), true);
    const changed = [...inputs]; changed[0] = (BigInt(changed[0]) + 1n).toString();
    assert.equal(client.verify(vk, proof, changed), false);
  });
}
const zeroProof = client.parseSnarkJsProof(load('proof-zero.json'));
const zeroInputs = load('public-zero.json');
for (const missing of ['', ' ', '\t\n']) {
  test('blank public scalar is rejected rather than accepted as zero: ' + JSON.stringify(missing), () => {
    const inputs = [...zeroInputs];
    const index = inputs.findIndex(x => BigInt(x) === 0n);
    assert.ok(index >= 0);
    inputs[index] = missing;
    assert.throws(() => client.verify(vk, zeroProof, inputs), /INVALID_STRING_SCALAR/);
    assert.throws(() => client.exportCalldata(zeroProof, inputs), /INVALID_STRING_SCALAR/);
  });
}
test('explicit zero forms and trimmed nonempty strings remain accepted', () => {
  for (const value of [0, 0n, '0', '0x0', ' 0 ']) {
    const inputs = [...zeroInputs]; inputs[inputs.findIndex(x => BigInt(x) === 0n)] = value;
    assert.equal(client.verify(vk, zeroProof, inputs), true);
  }
});
