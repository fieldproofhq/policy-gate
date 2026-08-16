import mod from './worker.js';

const env = {
  PAY_TO: '0x07C2383008a9ed30581f27Db5531E19411c94fb3',
  FREE_MODE: 'false',
  NETWORK: 'eip155:8453',
  PRICE_USD: '0.005',
};
const ctx = { waitUntil() {}, passThroughOnException() {} };

let fail = 0;
const ok = (n, c, x = '') => { console.log((c ? '  PASS  ' : '  FAIL  ') + n + (x ? '  ' + x : '')); if (!c) fail++; };

const r = await mod.fetch(new Request('https://policy-gate.3labsio.workers.dev/v1/check', {
  method: 'POST', headers: { 'content-type': 'application/json' },
  body: JSON.stringify({ policy_id: 'default-action-tiers', request: { action: 'docs.read' } }),
}), env, ctx);

ok('unpaid check returns 402', r.status === 402, `-> ${r.status}`);
const v2 = JSON.parse(Buffer.from(r.headers.get('PAYMENT-REQUIRED'), 'base64').toString('utf8'));
const bz = v2.extensions?.bazaar;
const info = bz?.info, schema = bz?.schema;

ok('schema declares Draft 2020-12', schema?.$schema === 'https://json-schema.org/draft/2020-12/schema', `-> ${schema?.$schema}`);
ok('schema requires input', Array.isArray(schema?.required) && schema.required.includes('input'));
ok('schema defines properties.input', !!schema?.properties?.input);
ok('input.type pinned to http', schema?.properties?.input?.properties?.type?.const === 'http');

const allowed = Object.keys(schema?.properties?.input?.properties || {});
const extra = Object.keys(info?.input || {}).filter((k) => !allowed.includes(k));
ok('info.input has no key the schema rejects', extra.length === 0, extra.length ? `stray: ${extra.join(', ')}` : '');

const missing = (schema?.properties?.input?.required || []).filter((k) => !(k in (info?.input || {})));
ok('info.input carries every required key', missing.length === 0, missing.length ? `missing: ${missing.join(', ')}` : '');

const descs = [v2.resource?.description, ...(v2.accepts || []).map((a) => a.description)].filter(Boolean);
ok('descriptions within 500 chars', descs.every((d) => d.length <= 500), `longest ${Math.max(0, ...descs.map((d) => d.length))}`);

console.log(fail ? `\n${fail} FAILED` : '\nbazaar declaration is spec-shaped');
process.exit(fail ? 1 : 0);
