const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');

const vector = JSON.parse(
  fs.readFileSync(
    path.join(__dirname, 'fixtures', 'measurement_attestation_signing_vector.json'),
    'utf8',
  ),
);

function canonical(value) {
  if (value === null) return 'null';
  if (value === true) return 'true';
  if (value === false) return 'false';
  if (typeof value === 'number') {
    if (!Number.isSafeInteger(value)) throw new Error('only safe integers are allowed');
    return String(value);
  }
  if (typeof value === 'string') return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`;
  if (typeof value === 'object') {
    const keys = Object.keys(value).sort();
    return `{${keys.map(key => `${JSON.stringify(key)}:${canonical(value[key])}`).join(',')}}`;
  }
  throw new Error(`unsupported JSON type: ${typeof value}`);
}

test('Node and Python share the measurement attestation signing vector', () => {
  const serialized = canonical(vector.payload);
  assert.equal(serialized, vector.canonical);

  const pkcs8Prefix = Buffer.from('302e020100300506032b657004220420', 'hex');
  const privateKey = crypto.createPrivateKey({
    key: Buffer.concat([pkcs8Prefix, Buffer.from(vector.seedHex, 'hex')]),
    format: 'der',
    type: 'pkcs8',
  });
  const payload = Buffer.concat([
    Buffer.from(vector.domain, 'utf8'),
    Buffer.from(serialized, 'utf8'),
  ]);
  const signature = crypto.sign(null, payload, privateKey);
  assert.equal(signature.toString('base64'), vector.signatureBase64);

  const publicKey = crypto.createPublicKey(vector.publicKeyPem);
  assert.equal(
    crypto.verify(null, payload, publicKey, Buffer.from(vector.signatureBase64, 'base64')),
    true,
  );
  const der = publicKey.export({ type: 'spki', format: 'der' });
  assert.equal(
    `ed25519:${crypto.createHash('sha256').update(der).digest('hex')}`,
    vector.keyId,
  );
});
